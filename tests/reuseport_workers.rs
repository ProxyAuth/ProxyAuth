//! Mode « un socket SO_REUSEPORT par worker » : toutes les connexions
//! sont servies, et réparties sur plusieurs workers par le noyau.

use proxyauth::hyper_web::{App, HttpResponse, HttpServer, web};
use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};

async fn who() -> HttpResponse {
    let name = std::thread::current().name().unwrap_or("?").to_string();
    HttpResponse::Ok().body(name)
}

fn reuseport_listener() -> TcpListener {
    use socket2::{Domain, Protocol, Socket, Type};
    let s = Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP)).unwrap();
    s.set_reuse_address(true).unwrap();
    s.set_reuse_port(true).unwrap();
    s.bind(&"127.0.0.1:0".parse::<SocketAddr>().unwrap().into())
        .unwrap();
    s.listen(1024).unwrap();
    s.into()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn connections_are_spread_over_worker_sockets() {
    let lst = reuseport_listener();
    let port = lst.local_addr().unwrap().port();
    let server = HttpServer::new(|| App::new().default_service(web::to(who)))
        .workers(4)
        .listen(lst)
        .unwrap()
        .run();
    let _server = tokio::spawn(server);

    let counts = tokio::task::spawn_blocking(move || {
        let mut counts: HashMap<String, usize> = HashMap::new();
        // Ports source différents à chaque connexion : le hachage du
        // noyau les répartit entre les sockets des workers.
        for _ in 0..400 {
            let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
            s.write_all(b"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
                .unwrap();
            let mut buf = String::new();
            s.read_to_string(&mut buf).unwrap();
            assert!(buf.starts_with("HTTP/1.1 200"), "{buf}");
            let worker = buf.rsplit("\r\n\r\n").next().unwrap().to_string();
            *counts.entry(worker).or_default() += 1;
        }
        counts
    })
    .await
    .unwrap();

    println!("{counts:?}");
    assert_eq!(counts.values().sum::<usize>(), 400);
    assert!(
        counts.keys().all(|k| k.starts_with("proxyauth-worker-")),
        "served outside the workers: {counts:?}"
    );
    assert!(
        counts.len() >= 3,
        "connections should land on several workers, got {counts:?}"
    );
}
