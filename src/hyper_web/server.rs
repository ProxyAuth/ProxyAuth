//! Serveur HTTP/1.1 + HTTP/2 (clair ou TLS) basé sur hyper.
//!
//! Même modèle d'exécution qu'actix-web, pour que le code métier (et ses
//! hypothèses) restent valables :
//! * `workers(n)` threads, chacun avec son propre runtime tokio
//!   mono-thread + `LocalSet` ; les futures des handlers n'ont donc pas
//!   besoin d'être `Send` ;
//! * l'application est construite une fois par worker via la closure
//!   passée à [`HttpServer::new`] ;
//! * chaque worker a son propre socket d'écoute par adresse
//!   (`SO_REUSEPORT`) et le noyau répartit les connexions entre eux ; si
//!   ce n'est pas possible, un thread d'acceptation unique distribue
//!   chaque connexion au worker qui en a le moins en cours ;
//! * SIGINT/SIGTERM déclenchent un arrêt gracieux : plus d'`accept`, les
//!   connexions en cours sont drainées pendant au plus
//!   `shutdown_timeout` (30 s par défaut, comme actix).

use super::app::{App, AppService, ServiceRequest};
use super::body::Body;
use super::extract::Payload;
use http::header::{self, HeaderValue};
use http::{Request, Response, Uri, Version};
use hyper::body::Incoming;
use hyper_util::rt::{TokioIo, TokioTimer};
use hyper_util::server::conn::auto;
use once_cell::sync::Lazy;
use std::convert::Infallible;
use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::rc::Rc;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;
use std::sync::atomic::{AtomicUsize, Ordering};
use tokio::sync::{mpsc, oneshot, watch};
use tracing::{debug, error, info, warn};

/// Délai maximal d'une poignée de main TLS, compté depuis la remise de
/// la connexion au worker. actix utilisait 3 s ; lors d'un afflux de
/// milliers de nouvelles connexions, les poignées de main (signature
/// RSA/ECDSA, coûteuse en CPU) font la queue et dépassaient ce délai :
/// le serveur coupait des connexions saines (« tls handshake eof » côté
/// client). 10 s laisse le temps d'absorber le pic, tout en coupant
/// les connexions qui ne parlent jamais.
const TLS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

// ─── Signal d'arrêt global ───────────────────────────────────────────

static SHUTDOWN: Lazy<watch::Sender<bool>> = Lazy::new(|| watch::channel(false).0);
static SIGNALS: std::sync::Once = std::sync::Once::new();

/// Déclenche l'arrêt gracieux de tous les serveurs du processus.
pub fn trigger_shutdown() {
    let _ = SHUTDOWN.send(true);
}

fn install_signal_handlers() {
    SIGNALS.call_once(|| {
        let fut = async {
            #[cfg(unix)]
            {
                use tokio::signal::unix::{SignalKind, signal};
                let mut term = match signal(SignalKind::terminate()) {
                    Ok(s) => s,
                    Err(e) => {
                        error!("hyper_web: cannot install SIGTERM handler: {e}");
                        return;
                    }
                };
                tokio::select! {
                    _ = tokio::signal::ctrl_c() => info!("SIGINT received, starting graceful shutdown"),
                    _ = term.recv() => info!("SIGTERM received, starting graceful shutdown"),
                }
            }
            #[cfg(not(unix))]
            {
                let _ = tokio::signal::ctrl_c().await;
                info!("Ctrl-C received, starting graceful shutdown");
            }
            trigger_shutdown();
        };
        match tokio::runtime::Handle::try_current() {
            Ok(h) => {
                h.spawn(fut);
            }
            Err(_) => {
                std::thread::spawn(move || {
                    if let Ok(rt) = tokio::runtime::Builder::new_current_thread()
                        .enable_all()
                        .build()
                    {
                        rt.block_on(fut);
                    }
                });
            }
        }
    });
}

// ─── Exécuteur local pour HTTP/2 ─────────────────────────────────────

#[derive(Clone, Copy, Debug)]
struct LocalExec;

impl<F> hyper::rt::Executor<F> for LocalExec
where
    F: Future + 'static,
{
    fn execute(&self, fut: F) {
        tokio::task::spawn_local(fut);
    }
}

// ─── HttpServer ──────────────────────────────────────────────────────

/// Protocole accepté sur une connexion.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum ConnProtocol {
    /// HTTP/1.1 et HTTP/2 (détection de la préface h2 / ALPN).
    #[default]
    Auto,
    Http1,
    Http2,
}

/// Choix de la configuration TLS d'après le nom SNI du ClientHello —
/// permet par exemple un ALPN différent par vhost.
pub type TlsSelector = Arc<dyn Fn(Option<&str>) -> Arc<rustls::ServerConfig> + Send + Sync>;

#[derive(Clone)]
enum Tls {
    Fixed(Arc<rustls::ServerConfig>),
    BySni(TlsSelector),
}

struct Listener {
    lst: std::net::TcpListener,
    tls: Option<Tls>,
    protocol: ConnProtocol,
}

/// Les trois variantes de connexion, construites une fois par worker.
struct Builders {
    auto: auto::Builder<LocalExec>,
    h1: auto::Builder<LocalExec>,
    h2: auto::Builder<LocalExec>,
}

impl Builders {
    fn get(&self, p: ConnProtocol) -> &auto::Builder<LocalExec> {
        match p {
            ConnProtocol::Auto => &self.auto,
            ConnProtocol::Http1 => &self.h1,
            ConnProtocol::Http2 => &self.h2,
        }
    }
}

#[derive(Clone)]
struct ServerOptions {
    backlog: i32,
    keep_alive: Duration,
    max_connections: usize,
    client_request_timeout: Duration,
    shutdown_timeout: Duration,
}

pub struct HttpServer<F> {
    factory: F,
    workers: usize,
    opts: ServerOptions,
    listeners: Vec<Listener>,
}

impl<F> HttpServer<F>
where
    F: Fn() -> App + Send + Clone + 'static,
{
    pub fn new(factory: F) -> Self {
        HttpServer {
            factory,
            workers: std::thread::available_parallelism()
                .map(|n| n.get())
                .unwrap_or(1),
            opts: ServerOptions {
                backlog: 4096,
                keep_alive: Duration::from_secs(5),
                max_connections: 25_000,
                client_request_timeout: Duration::from_secs(5),
                shutdown_timeout: Duration::from_secs(30),
            },
            listeners: Vec::new(),
        }
    }

    pub fn workers(mut self, n: usize) -> Self {
        self.workers = n.max(1);
        self
    }

    /// Délai d'inactivité d'une connexion keep-alive ; `0` désactive le
    /// keep-alive.
    pub fn keep_alive(mut self, d: Duration) -> Self {
        self.opts.keep_alive = d;
        self
    }

    /// File d'attente des sockets d'écoute supplémentaires créés pour
    /// chaque worker (mode `SO_REUSEPORT`, voir [`HttpServer::run`]).
    pub fn backlog(mut self, n: u32) -> Self {
        self.opts.backlog = i32::try_from(n).unwrap_or(i32::MAX);
        self
    }

    /// Connexions simultanées maximales **par worker** (comme actix).
    pub fn max_connections(mut self, n: usize) -> Self {
        self.opts.max_connections = n.max(1);
        self
    }

    /// Délai pour recevoir la tête de requête ; `0` désactive.
    pub fn client_request_timeout(mut self, d: Duration) -> Self {
        self.opts.client_request_timeout = d;
        self
    }

    pub fn shutdown_timeout(mut self, secs: u64) -> Self {
        self.opts.shutdown_timeout = Duration::from_secs(secs);
        self
    }

    pub fn listen(self, lst: std::net::TcpListener) -> io::Result<Self> {
        self.listen_with(lst, None, ConnProtocol::Auto)
    }

    pub fn listen_rustls_0_23(
        self,
        lst: std::net::TcpListener,
        cfg: rustls::ServerConfig,
    ) -> io::Result<Self> {
        self.listen_with(lst, Some(Tls::Fixed(Arc::new(cfg))), ConnProtocol::Auto)
    }

    /// Écouteur en clair limité à un protocole.
    pub fn listen_protocol(self, lst: std::net::TcpListener, protocol: ConnProtocol) -> io::Result<Self> {
        self.listen_with(lst, None, protocol)
    }

    /// Écouteur TLS dont la configuration est choisie par nom SNI. Le
    /// protocole de chaque connexion suit l'ALPN négocié.
    pub fn listen_rustls_sni(self, lst: std::net::TcpListener, selector: TlsSelector) -> io::Result<Self> {
        self.listen_with(lst, Some(Tls::BySni(selector)), ConnProtocol::Auto)
    }

    fn listen_with(
        mut self,
        lst: std::net::TcpListener,
        tls: Option<Tls>,
        protocol: ConnProtocol,
    ) -> io::Result<Self> {
        lst.set_nonblocking(true)?;
        self.listeners.push(Listener { lst, tls, protocol });
        Ok(self)
    }

    pub fn bind(self, addr: impl std::net::ToSocketAddrs) -> io::Result<Self> {
        let lst = std::net::TcpListener::bind(addr)?;
        self.listen(lst)
    }

    /// Démarre l'accepteur et les workers immédiatement ; le [`Server`]
    /// renvoyé se résout quand tous se sont arrêtés.
    pub fn run(self) -> Server {
        install_signal_handlers();

        let n = self.workers;
        let load: Arc<[AtomicUsize]> = (0..n).map(|_| AtomicUsize::new(0)).collect();
        let listener_cfg: Arc<Vec<ListenerCfg>> = Arc::new(
            self.listeners
                .iter()
                .map(|l| ListenerCfg {
                    tls: l.tls.clone(),
                    protocol: l.protocol,
                })
                .collect(),
        );

        let mut done = Vec::with_capacity(n + 1);

        // Mode privilégié : un socket d'écoute par worker sur chaque
        // adresse (`SO_REUSEPORT`). Le noyau répartit les connexions
        // entre eux ; aucun passage de connexion d'un thread à l'autre.
        // C'est l'architecture des serveurs Rust en tête des benchmarks
        // (TechEmpower : un runtime mono-thread par cœur, chacun son
        // socket). Repli sur un thread d'acceptation si les sockets
        // supplémentaires ne peuvent pas être créés (socket d'origine
        // sans `SO_REUSEPORT`, plateforme sans support…).
        let originals: Vec<std::net::TcpListener> =
            self.listeners.into_iter().map(|l| l.lst).collect();
        let (per_worker, originals) = match reuseport_siblings(&originals, n, self.opts.backlog) {
            Ok(siblings) => (Some(siblings), originals),
            Err(e) => {
                debug!("SO_REUSEPORT per worker unavailable ({e}); using a single accept thread");
                (None, originals)
            }
        };

        if let Some(mut siblings) = per_worker {
            // Worker 0 reprend les sockets d'origine.
            let mut sets: Vec<Vec<std::net::TcpListener>> = Vec::with_capacity(n);
            sets.push(originals);
            sets.append(&mut siblings);
            for (idx, set) in sets.into_iter().enumerate() {
                let factory = self.factory.clone();
                let opts = self.opts.clone();
                let cfg = listener_cfg.clone();
                let load = load.clone();
                let (tx, rx) = oneshot::channel::<io::Result<()>>();
                let spawned = std::thread::Builder::new()
                    .name(format!("proxyauth-worker-{idx}"))
                    .spawn(move || {
                        let res = run_worker(idx, factory, Source::Listeners(set), cfg, load, opts);
                        let _ = tx.send(res);
                    });
                if let Err(e) = spawned {
                    return Server::failed(e);
                }
                done.push(rx);
            }
        } else {
            let mut senders = Vec::with_capacity(n);
            for idx in 0..n {
                let (conn_tx, conn_rx) = mpsc::unbounded_channel::<Conn>();
                senders.push(conn_tx);
                let factory = self.factory.clone();
                let opts = self.opts.clone();
                let cfg = listener_cfg.clone();
                let load = load.clone();
                let (tx, rx) = oneshot::channel::<io::Result<()>>();
                let spawned = std::thread::Builder::new()
                    .name(format!("proxyauth-worker-{idx}"))
                    .spawn(move || {
                        let res = run_worker(idx, factory, Source::Channel(conn_rx), cfg, load, opts);
                        let _ = tx.send(res);
                    });
                if let Err(e) = spawned {
                    return Server::failed(e);
                }
                done.push(rx);
            }

            // Un seul thread d'acceptation, qui confie chaque connexion au
            // worker qui en a le moins en cours.
            let max = self.opts.max_connections;
            let (tx, rx) = oneshot::channel::<io::Result<()>>();
            let spawned = std::thread::Builder::new()
                .name("proxyauth-accept".to_string())
                .spawn(move || {
                    let res = run_acceptor(originals, senders, load, max);
                    let _ = tx.send(res);
                });
            if let Err(e) = spawned {
                return Server::failed(e);
            }
            done.push(rx);
        }

        Server {
            fut: Box::pin(async move {
                let mut first_err = None;
                for rx in done {
                    match rx.await {
                        Ok(Ok(())) => {}
                        Ok(Err(e)) => {
                            first_err.get_or_insert(e);
                        }
                        Err(_) => {
                            first_err.get_or_insert(io::Error::other("server thread panicked"));
                        }
                    }
                }
                match first_err {
                    Some(e) => Err(e),
                    None => Ok(()),
                }
            }),
        }
    }
}

/// Serveur en cours d'exécution.
pub struct Server {
    fut: Pin<Box<dyn Future<Output = io::Result<()>> + Send>>,
}

impl Server {
    fn failed(e: io::Error) -> Self {
        Server {
            fut: Box::pin(async move { Err(e) }),
        }
    }
}

impl Future for Server {
    type Output = io::Result<()>;
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        self.fut.as_mut().poll(cx)
    }
}

// ─── Sockets SO_REUSEPORT par worker ─────────────────────────────────

/// Pour chaque socket d'origine, crée `workers - 1` sockets frères
/// liés à la même adresse avec `SO_REUSEPORT`. Résultat indexé par
/// worker (1..workers), chacun avec un socket par adresse, dans l'ordre
/// des sockets d'origine.
///
/// Doit être appelé avant l'abandon des droits root : lier un port
/// < 1024 l'exige.
fn reuseport_siblings(
    originals: &[std::net::TcpListener],
    workers: usize,
    backlog: i32,
) -> io::Result<Vec<Vec<std::net::TcpListener>>> {
    use socket2::{Domain, Protocol, SockRef, Socket, Type};

    let mut per_worker: Vec<Vec<std::net::TcpListener>> =
        (1..workers).map(|_| Vec::with_capacity(originals.len())).collect();
    if workers <= 1 {
        return Ok(per_worker);
    }
    for lst in originals {
        let sock = SockRef::from(lst);
        if !sock.reuse_port()? {
            return Err(io::Error::other("listener was not created with SO_REUSEPORT"));
        }
        let addr = lst.local_addr()?;
        for set in per_worker.iter_mut() {
            let domain = if addr.is_ipv4() { Domain::IPV4 } else { Domain::IPV6 };
            let s = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?;
            if addr.is_ipv6() {
                s.set_only_v6(sock.only_v6().unwrap_or(false))?;
            }
            s.set_reuse_address(true)?;
            s.set_reuse_port(true)?;
            // Hérité par les connexions acceptées sous Linux.
            s.set_nodelay(true)?;
            s.set_nonblocking(true)?;
            s.bind(&addr.into())?;
            s.listen(backlog)?;
            set.push(s.into());
        }
    }
    Ok(per_worker)
}

/// D'où un worker reçoit ses connexions.
enum Source {
    /// Ses propres sockets d'écoute (mode `SO_REUSEPORT`).
    Listeners(Vec<std::net::TcpListener>),
    /// Le canal du thread d'acceptation (mode de repli).
    Channel(mpsc::UnboundedReceiver<Conn>),
}

// ─── Accepteur ───────────────────────────────────────────────────────

/// Connexion acceptée, en route vers un worker.
struct Conn {
    stream: std::net::TcpStream,
    peer: SocketAddr,
    local_addr: Option<SocketAddr>,
    listener: usize,
}

#[derive(Clone)]
struct ListenerCfg {
    tls: Option<Tls>,
    protocol: ConnProtocol,
}

/// Choisit le worker le moins chargé ; à charge égale, tourne en
/// rond pour ne pas toujours favoriser le premier. `None` si tous ont
/// atteint `max`.
fn pick_worker(load: &[AtomicUsize], start: usize, max: usize) -> Option<usize> {
    let n = load.len();
    let mut best: Option<(usize, usize)> = None;
    for k in 0..n {
        let i = (start + k) % n;
        let l = load[i].load(Ordering::Relaxed);
        if l < max && best.is_none_or(|(_, bl)| l < bl) {
            best = Some((i, l));
            if l == 0 {
                break;
            }
        }
    }
    best.map(|(i, _)| i)
}

fn run_acceptor(
    listeners: Vec<std::net::TcpListener>,
    senders: Vec<mpsc::UnboundedSender<Conn>>,
    load: Arc<[AtomicUsize]>,
    max: usize,
) -> io::Result<()> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    rt.block_on(async move {
        let senders = Arc::new(senders);
        let rr = Arc::new(AtomicUsize::new(0));
        let mut tasks = Vec::new();
        for (idx, l) in listeners.into_iter().enumerate() {
            let lst = tokio::net::TcpListener::from_std(l)?;
            let senders = senders.clone();
            let load = load.clone();
            let rr = rr.clone();
            tasks.push(tokio::spawn(async move {
                let local_addr = lst.local_addr().ok();
                loop {
                    // Tous les workers pleins : on cesse d'accepter (le
                    // noyau garde les connexions dans la file d'attente).
                    let worker = loop {
                        let start = rr.fetch_add(1, Ordering::Relaxed);
                        match pick_worker(&load, start, max) {
                            Some(w) => break w,
                            None => tokio::time::sleep(Duration::from_millis(5)).await,
                        }
                    };
                    let (stream, peer) = match lst.accept().await {
                        Ok(v) => v,
                        Err(e) => {
                            // EMFILE/ENFILE (plus de descripteurs) : on
                            // patiente plutôt que de boucler, et on le dit
                            // — sinon le serveur semble juste « ramer ».
                            report_accept_error(&e);
                            tokio::time::sleep(Duration::from_millis(50)).await;
                            continue;
                        }
                    };
                    let _ = stream.set_nodelay(true);
                    let stream = match stream.into_std() {
                        Ok(s) => s,
                        Err(e) => {
                            debug!("cannot hand connection {peer} to a worker: {e}");
                            continue;
                        }
                    };
                    load[worker].fetch_add(1, Ordering::Relaxed);
                    let conn = Conn {
                        stream,
                        peer,
                        local_addr,
                        listener: idx,
                    };
                    if senders[worker].send(conn).is_err() {
                        load[worker].fetch_sub(1, Ordering::Relaxed);
                    }
                }
            }));
        }

        wait_shutdown(&mut SHUTDOWN.subscribe()).await;
        for t in &tasks {
            t.abort();
        }
        // Les `senders` sont libérés avec les tâches : chaque worker voit
        // son canal se fermer et passe en drainage.
        Ok(())
    })
}

/// Journalise une erreur d'`accept()`, au plus une fois toutes les 10 s.
fn report_accept_error(e: &io::Error) {
    static LAST: std::sync::Mutex<Option<std::time::Instant>> = std::sync::Mutex::new(None);
    let fd_exhausted = matches!(e.raw_os_error(), Some(code) if code == 24 || code == 23);
    let mut last = LAST.lock().unwrap_or_else(|p| p.into_inner());
    if last.is_some_and(|t| t.elapsed() < Duration::from_secs(10)) {
        return;
    }
    *last = Some(std::time::Instant::now());
    if fd_exhausted {
        warn!(
            "accept() failed: {e} — the open-files limit is exhausted, new connections are waiting in the kernel queue; raise LimitNOFILE / ulimit -n or lower max_connections"
        );
    } else {
        warn!("accept() failed: {e}");
    }
}

// ─── Worker ──────────────────────────────────────────────────────────

/// Décrémente la charge du worker quand la connexion se termine.
struct LoadGuard {
    load: Arc<[AtomicUsize]>,
    idx: usize,
}

impl Drop for LoadGuard {
    fn drop(&mut self) {
        self.load[self.idx].fetch_sub(1, Ordering::Relaxed);
    }
}

fn run_worker<F>(
    idx: usize,
    factory: F,
    source: Source,
    listeners: Arc<Vec<ListenerCfg>>,
    load: Arc<[AtomicUsize]>,
    opts: ServerOptions,
) -> io::Result<()>
where
    F: Fn() -> App,
{
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let local = tokio::task::LocalSet::new();

    local.block_on(&rt, async move {
        let app = factory().into_service();
        let builders = Rc::new(Builders {
            auto: make_builder(&opts),
            h1: make_builder(&opts).http1_only(),
            h2: make_builder(&opts).http2_only(),
        });
        let mut shutdown = SHUTDOWN.subscribe();

        match source {
            Source::Listeners(own) => {
                let max = opts.max_connections;
                let mut tasks = Vec::with_capacity(own.len());
                for (li, std_lst) in own.into_iter().enumerate() {
                    let lst = tokio::net::TcpListener::from_std(std_lst)?;
                    let cfg = listeners[li].clone();
                    let app = app.clone();
                    let builders = builders.clone();
                    let load = load.clone();
                    tasks.push(tokio::task::spawn_local(async move {
                        let local_addr = lst.local_addr().ok();
                        loop {
                            // Plein : on cesse d'accepter, le noyau garde les
                            // connexions dans la file de ce socket.
                            while load[idx].load(Ordering::Relaxed) >= max {
                                tokio::time::sleep(Duration::from_millis(5)).await;
                            }
                            let (stream, peer) = match lst.accept().await {
                                Ok(v) => v,
                                Err(e) => {
                                    report_accept_error(&e);
                                    tokio::time::sleep(Duration::from_millis(50)).await;
                                    continue;
                                }
                            };
                            let _ = stream.set_nodelay(true);
                            load[idx].fetch_add(1, Ordering::Relaxed);
                            let guard = LoadGuard {
                                load: load.clone(),
                                idx,
                            };
                            tokio::task::spawn_local(handle_connection(
                                stream,
                                peer,
                                local_addr,
                                cfg.clone(),
                                app.clone(),
                                builders.clone(),
                                guard,
                            ));
                        }
                    }));
                }
                wait_shutdown(&mut shutdown).await;
                for t in &tasks {
                    t.abort();
                }
            }
            Source::Channel(mut conns) => loop {
                let conn = tokio::select! {
                    c = conns.recv() => match c {
                        Some(c) => c,
                        None => break,
                    },
                    _ = wait_shutdown(&mut shutdown) => break,
                };
                let guard = LoadGuard {
                    load: load.clone(),
                    idx,
                };
                let stream = match tokio::net::TcpStream::from_std(conn.stream) {
                    Ok(s) => s,
                    Err(e) => {
                        debug!("worker {idx}: cannot adopt connection {}: {e}", conn.peer);
                        continue;
                    }
                };
                let cfg = listeners[conn.listener].clone();
                tokio::task::spawn_local(handle_connection(
                    stream,
                    conn.peer,
                    conn.local_addr,
                    cfg,
                    app.clone(),
                    builders.clone(),
                    guard,
                ));
            },
        }

        // Arrêt : chaque connexion a reçu le signal et termine proprement
        // sa requête en cours (voir `serve`). On attend qu'elles aient
        // toutes rendu leur place, dans la limite de `shutdown_timeout`.
        let deadline = tokio::time::Instant::now() + opts.shutdown_timeout;
        while load[idx].load(Ordering::Relaxed) > 0 {
            if tokio::time::Instant::now() >= deadline {
                warn!(
                    "worker {idx}: graceful shutdown timed out after {:?}, closing remaining connections",
                    opts.shutdown_timeout
                );
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        Ok(())
    })
}

async fn wait_shutdown(rx: &mut watch::Receiver<bool>) {
    while !*rx.borrow_and_update() {
        if rx.changed().await.is_err() {
            // Émetteur statique : n'arrive jamais, mais ne pas boucler.
            std::future::pending::<()>().await;
        }
    }
}

fn make_builder(opts: &ServerOptions) -> auto::Builder<LocalExec> {
    let mut b = auto::Builder::new(LocalExec);
    let keep_alive = !opts.keep_alive.is_zero();

    // hyper arme ce minuteur dès que la connexion attend une tête de
    // requête, y compris entre deux requêtes keep-alive : il couvre donc
    // à la fois le `client_request_timeout` et le délai d'inactivité
    // keep-alive d'actix.
    let head_timeout = if keep_alive {
        opts.keep_alive.max(opts.client_request_timeout)
    } else {
        opts.client_request_timeout
    };
    {
        let mut h1 = b.http1();
        h1.timer(TokioTimer::new())
            .keep_alive(keep_alive)
            // Doc hyper : regroupe les écritures des réponses en pipeline
            // en un seul flush (moins d'appels système quand un client
            // envoie plusieurs requêtes d'affilée sur la connexion).
            .pipeline_flush(true);
        if head_timeout.is_zero() {
            h1.header_read_timeout(None);
        } else {
            h1.header_read_timeout(head_timeout);
        }
    }
    {
        let mut h2 = b.http2();
        // Fenêtres de contrôle de flux : on garde celles de hyper (1 Mio
        // par flux et par connexion). `adaptive_window(true)` les
        // ramènerait à 64 Kio au démarrage (valeur de la RFC) en
        // attendant d'avoir mesuré le débit × latence : moins bien pour
        // la plupart des clients.
        h2.timer(TokioTimer::new())
            // Protection « rapid reset » (CVE-2023-44487) : borne le
            // nombre de flux annulés par le client avant d'être servis.
            .max_pending_accept_reset_streams(Some(20));
        if keep_alive {
            h2.keep_alive_interval(opts.keep_alive)
                .keep_alive_timeout(Duration::from_secs(20));
        }
    }
    b
}

async fn handle_connection(
    stream: tokio::net::TcpStream,
    peer: SocketAddr,
    local_addr: Option<SocketAddr>,
    cfg: ListenerCfg,
    app: AppService,
    builders: Rc<Builders>,
    _guard: LoadGuard,
) {
    let Some(tls) = cfg.tls else {
        let builder = builders.get(cfg.protocol);
        serve(TokioIo::new(stream), peer, local_addr, false, app, builder).await;
        return;
    };

    let handshake = async {
        match tls {
            Tls::Fixed(c) => tokio_rustls::TlsAcceptor::from(c).accept(stream).await,
            Tls::BySni(select) => {
                let start = tokio_rustls::LazyConfigAcceptor::new(
                    rustls::server::Acceptor::default(),
                    stream,
                )
                .await?;
                let c = select(start.client_hello().server_name());
                start.into_stream(c).await
            }
        }
    };
    let tls_stream = match tokio::time::timeout(TLS_HANDSHAKE_TIMEOUT, handshake).await {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => {
            debug!("TLS handshake with {peer} failed: {e}");
            return;
        }
        Err(_) => {
            debug!("TLS handshake with {peer} timed out");
            return;
        }
    };

    // Le protocole suit l'ALPN négocié ; sans ALPN, celui de l'écouteur.
    let negotiated = match tls_stream.get_ref().1.alpn_protocol() {
        Some(b"h2") => ConnProtocol::Http2,
        Some(b"http/1.1") => ConnProtocol::Http1,
        _ => cfg.protocol,
    };
    let builder = builders.get(negotiated);
    serve(TokioIo::new(tls_stream), peer, local_addr, true, app, builder).await;
}

async fn serve<I>(
    io: I,
    peer: SocketAddr,
    local_addr: Option<SocketAddr>,
    secure: bool,
    app: AppService,
    builder: &auto::Builder<LocalExec>,
) where
    I: hyper::rt::Read + hyper::rt::Write + Unpin + 'static,
{
    let svc = hyper::service::service_fn(move |req: Request<Incoming>| {
        let app = app.clone();
        async move { Ok::<_, Infallible>(handle(app, req, peer, local_addr, secure).await) }
    });
    let conn = builder.serve_connection(io, svc);
    tokio::pin!(conn);
    let mut rx = SHUTDOWN.subscribe();
    let res = tokio::select! {
        r = conn.as_mut() => r,
        _ = wait_shutdown(&mut rx) => {
            conn.as_mut().graceful_shutdown();
            conn.await
        }
    };
    if let Err(e) = res {
        debug!("connection {peer} closed with error: {e}");
    }
}

/// Une requête hyper → `ServiceRequest` → application → réponse hyper.
pub(crate) async fn handle(
    app: AppService,
    req: Request<Incoming>,
    peer: SocketAddr,
    local_addr: Option<SocketAddr>,
    secure: bool,
) -> Response<Body> {
    let (parts, body) = req.into_parts();
    let is_head = parts.method == http::Method::HEAD;
    let mut headers = parts.headers;

    // HTTP/2 transporte l'hôte dans `:authority` et l'URI sous forme
    // absolue. On ramène tout à la forme HTTP/1.1 (Host + chemin
    // relatif), celle que le code de ProxyAuth a toujours manipulée.
    let uri = normalize_uri(parts.uri, parts.version, &mut headers);

    let http_req = app.make_request(
        parts.method,
        uri,
        parts.version,
        headers,
        Some(peer),
        local_addr,
        secure,
    );
    let payload = Payload::new(incoming_to_body(body));
    let res = app.call(ServiceRequest::new(http_req, payload)).await;
    let mut res = res.into_response();
    if is_head {
        strip_body_for_head(&mut res);
    }
    res.into_hyper()
}

/// Une réponse à HEAD ne doit porter aucun corps (RFC 9110 § 9.3.2).
///
/// En HTTP/1.1 hyper s'en charge seul, mais pas en HTTP/2 : son serveur
/// h2 ne connaît pas la méthode et enverrait le corps en trames DATA,
/// ce que le client traite comme une erreur de protocole (curl : code
/// 92, « stream error in the HTTP/2 framing layer »). actix-web le
/// retirait automatiquement ; on fait de même ici, pour tous les
/// protocoles, en conservant (ou en calculant) `Content-Length` pour
/// que HEAD annonce la même taille que le GET correspondant.
fn strip_body_for_head(res: &mut super::response::HttpResponse) {
    let body = res.take_body();
    let status = res.status().as_u16();
    let may_have_length = !(status < 200 || status == 204 || status == 304);
    if may_have_length && !res.headers().contains_key(header::CONTENT_LENGTH) {
        if let super::body::BodySize::Sized(n) = body.size() {
            res.headers_mut().insert(header::CONTENT_LENGTH, HeaderValue::from(n));
        }
    }
    // `body` (éventuellement un flux venant du backend) est abandonné ici.
}

fn normalize_uri(uri: Uri, version: Version, headers: &mut http::HeaderMap) -> Uri {
    if uri.authority().is_none() {
        return uri;
    }
    if version == Version::HTTP_2 && !headers.contains_key(header::HOST) {
        if let Some(auth) = uri.authority() {
            if let Ok(v) = HeaderValue::from_str(auth.as_str()) {
                headers.insert(header::HOST, v);
            }
        }
    }
    match uri.path_and_query() {
        Some(pq) => Uri::builder()
            .path_and_query(pq.clone())
            .build()
            .unwrap_or(uri),
        None => Uri::from_static("/"),
    }
}

pub(crate) fn incoming_to_body(body: Incoming) -> Body {
    use http_body_util::BodyExt;
    use futures_util::StreamExt;
    let stream = http_body_util::BodyStream::new(body.map_err(|e| Box::new(e) as super::body::BoxError))
        .filter_map(|frame| async move {
            match frame {
                Ok(f) => f.into_data().ok().map(Ok::<_, super::body::BoxError>),
                Err(e) => Some(Err(e)),
            }
        });
    Body::from_stream(stream)
}
