//! Limite de descripteurs de fichiers du processus (`RLIMIT_NOFILE`).
//!
//! Chaque connexion client consomme un descripteur, chaque connexion
//! vers un backend un autre. La limite « souple » par défaut de Linux
//! est de **1024** : au-delà d'environ 1000 connexions simultanées,
//! `accept()` échoue (EMFILE), les clients restent en file d'attente
//! puis expirent, et les connexions vers les backends ne s'ouvrent plus
//! (502). ProxyAuth la relève donc lui-même au démarrage, avant
//! d'abandonner les droits root, comme le font nginx
//! (`worker_rlimit_nofile`) ou HAProxy.

use nix::sys::resource::{Resource, getrlimit, setrlimit};

/// Plafond visé : largement assez pour un proxy, et la valeur maximale
/// usuelle de `fs.nr_open`.
const TARGET: u64 = 1_048_576;

/// Ce qui a été obtenu.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FdLimit {
    pub before: u64,
    pub after: u64,
}

fn nr_open() -> u64 {
    std::fs::read_to_string("/proc/sys/fs/nr_open")
        .ok()
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or(TARGET)
}

/// Relève la limite souple — et, si le processus en a le droit (root /
/// CAP_SYS_RESOURCE), la limite dure — vers [`TARGET`], bornée par
/// `fs.nr_open`. Sans privilège, la limite souple monte jusqu'à la
/// limite dure, ce qui est toujours permis.
pub fn raise() -> std::io::Result<FdLimit> {
    let (soft, hard) = getrlimit(Resource::RLIMIT_NOFILE).map_err(std::io::Error::from)?;
    let wanted = TARGET.min(nr_open());

    // Tentative privilégiée : souple = dure = `wanted` (sans jamais
    // abaisser une limite dure déjà plus haute).
    let new_hard = hard.max(wanted);
    if setrlimit(Resource::RLIMIT_NOFILE, wanted.min(new_hard), new_hard).is_err() {
        // Pas le droit de toucher la limite dure : souple → dure.
        setrlimit(Resource::RLIMIT_NOFILE, hard, hard).map_err(std::io::Error::from)?;
    }

    let (after, _) = getrlimit(Resource::RLIMIT_NOFILE).map_err(std::io::Error::from)?;
    Ok(FdLimit {
        before: soft,
        after,
    })
}

/// En dessous, ProxyAuth prévient au démarrage.
pub const COMFORTABLE: u64 = 65_536;

/// Connexions client simultanées tenables avec `limit` descripteurs :
/// une connexion client + au plus une vers un backend chacune, moins une
/// marge pour les fichiers, journaux et sockets d'écoute.
pub fn max_connections_for(limit: u64) -> u64 {
    limit.saturating_sub(256) / 2
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn raise_never_lowers_the_limit() {
        let (soft, _) = getrlimit(Resource::RLIMIT_NOFILE).unwrap();
        let l = raise().unwrap();
        assert_eq!(l.before, soft);
        assert!(l.after >= l.before);
    }

    #[test]
    fn capacity_counts_client_and_backend_sides() {
        assert_eq!(max_connections_for(1024), 384);
        assert_eq!(max_connections_for(100), 0);
    }
}
