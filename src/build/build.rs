use blake3;
// rand 0.10 : `RngCore` s'appelle `Rng`, et l'ancien `Rng` (les méthodes
// de commodité) s'appelle `RngExt`. `ChaCha8Rng` vient de `rand` via la
// feature `chacha`, ce qui évite de retirer un second `rand_core` dans
// le graphe de dépendances.
use rand::rngs::ChaCha8Rng;
use rand::seq::SliceRandom;
use rand::{Rng, RngExt, SeedableRng};
use std::env;
use std::fs;
use std::io::Write;
use std::path::Path;
use std::process;
use std::time::{SystemTime, UNIX_EPOCH};

pub fn identity(seed: u64) -> String {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards")
        .as_nanos();

    let mut input = Vec::with_capacity(24);
    input.extend_from_slice(&seed.to_be_bytes());
    input.extend_from_slice(&timestamp.to_be_bytes());

    let hash = blake3::hash(&input);

    let mut id = [0u8; 9];
    id.copy_from_slice(&hash.as_bytes()[..9]);

    // unicast + locally administered
    id[0] = (id[0] & 0b1111_1100) | 0b0000_0010;

    id.iter()
        .map(|b| format!("{:02X}", b))
        .collect::<Vec<_>>()
        .join(":")
}

/// Generates the build-time secret used as the HKDF salt in
/// key derivation and the token signature, via the `zerocrypt` vault
/// built in `token::vault::init`.
///
/// Unlike `identity()`, this draws `len` bytes directly from the OS
/// CSPRNG. That distinction matters: hashing a low-entropy seed to a
/// longer output does not create entropy, it only hides how little
/// there is. The entropy of the result here is the full `len * 8` bits.
///
/// This value is key material. It must not be truncated, nor shaped to
/// resemble a MAC address or any other identifier format.
pub fn build_secret_hex(len: usize) -> String {
    let mut buf = vec![0u8; len];
    getrandom::fill(&mut buf).expect("OS CSPRNG unavailable");
    buf.iter().map(|b| format!("{:02x}", b)).collect()
}

fn main() {
    let version = env::var("CARGO_PKG_VERSION").expect("CARGO_PKG_VERSION not set");

    if is_yanked_version(&version) {
        eprintln!("Build blocked: version {} is marked as yanked", version);
        process::exit(1);
    } else {
        println!("cargo:warning=Version {} is allowed to build", version);
    }

    // `thread_rng()` est renommé `rng()`. `gen_range` est renommé
    // `random_range` et vit sur `RngExt` ; `next_u64` vit sur `Rng`.
    let mut rng = rand::rng();
    let build_rand = rng.random_range(1..999_999_999);
    let mut rngr = rand::rng();
    let build_seed = rngr.next_u64();
    let build_seed2 = rng.random_range(10..99);

    let build_time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
        .to_string();

    let random_epoch: i64 = rng.random_range(0..999_999_999_999);
    let identity_str = identity(rng.random_range(1..999_999_999_999));
    let hk = build_secret_hex(32);

    println!("cargo:rustc-env=BUILD_TIME={}", build_time);
    println!("cargo:rustc-env=BUILD_RAND={}", build_rand);
    println!("cargo:rustc-env=BUILD_SEED={}", build_seed);
    println!("cargo:rustc-env=BUILD_SEED2={}", build_seed2);
    println!("cargo:rustc-env=BUILD_EPOCH_DATE={}", random_epoch);
    println!("cargo:rustc-env=BUILD_HK={}", hk);
    println!("cargo:rustc-env=id={}", identity_str);

    // SHUFFLE BUILD
    let mut fields = vec![
        "username".to_string(),
        "secret_with_timestamp".to_string(),
        "build_time".to_string(),
        "time_expire".to_string(),
        "build_rand".to_string(),
        "token_id".to_string(),
        "hk".to_string(),
    ];

    let mut shuffle_rng = ChaCha8Rng::seed_from_u64(build_seed);
    fields.shuffle(&mut shuffle_rng);

    let const_string = format!(
        "pub const SHUFFLED_ORDER: [&str; {}] = [{}];",
        fields.len(),
        fields
            .iter()
            .map(|s| format!("\"{}\"", s))
            .collect::<Vec<_>>()
            .join(", ")
    );

    let out_dir = std::env::var("OUT_DIR").unwrap();
    let dest_path = Path::new(&out_dir).join("shuffle_generated.rs");
    let mut f = fs::File::create(dest_path).unwrap();
    f.write_all(const_string.as_bytes()).unwrap();
}

fn is_yanked_version(version: &str) -> bool {
    let url = format!("https://proxyauth.app/config/build.json?v={}", version);

    let response = match reqwest::blocking::get(&url) {
        Ok(resp) => resp,
        Err(err) => {
            eprintln!("Failed to fetch build.json from {}: {}", url, err);
            return false;
        }
    };

    let json_text = match response.text() {
        Ok(text) => text,
        Err(err) => {
            eprintln!("Failed to read build.json content: {}", err);
            return false;
        }
    };

    let data: serde_json::Value = match serde_json::from_str(&json_text) {
        Ok(json) => json,
        Err(err) => {
            eprintln!("Failed to parse build.json: {}", err);
            return false;
        }
    };

    match data.get(version).and_then(|v| v.as_str()) {
        Some("yank") => true,
        _ => false,
    }
}
