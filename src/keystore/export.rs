use crate::build::build_info;
use crate::config::config::load_config;
use anyhow::Context;
use sequoia_openpgp::Result;
use sequoia_openpgp::cert::amalgamation::key::PrimaryKey;
use sequoia_openpgp::crypto::Password;
use sequoia_openpgp::packet::{Packet, UserID};
use sequoia_openpgp::policy::StandardPolicy;
use sequoia_openpgp::serialize::stream::*;
use sequoia_openpgp::{
    armor::{Kind as ArmorKind, Writer as ArmorWriter},
    cert::{Cert, CertBuilder},
    serialize::Serialize,
};
use std::fs::{File, create_dir_all};
use std::io::{BufWriter, Write};

/// Default location of config.json, used when no explicit path is
/// provided by the caller.
const DEFAULT_CONFIG_PATH: &str = "/etc/proxyauth/config/config.json";

/// Generates a new OpenPGP certificate for ProxyAuth's SSO keystore,
/// encrypts its secret key material with a passphrase derived from
/// AppConfig's `secret` field, and writes it to `key.asc`.
///
/// `config_path` is the path to `config.json`, used to load the
/// passphrase that will protect the exported private key. If `None`
/// is passed, `DEFAULT_CONFIG_PATH` is used instead.
pub fn export_as_file(config_path: Option<&str>) -> Result<()> {
    let dir = std::env::current_dir()?.to_str().unwrap().to_string();
    create_dir_all(&dir)?;

    // Fall back to the default config.json location if none was given.
    let config_path = config_path.unwrap_or(DEFAULT_CONFIG_PATH);

    // Load the application secret from config.json to use as the
    // passphrase protecting the exported private key.
    let app_config = load_config(config_path);
    let password = Password::from(app_config.secret.as_str());

    // Generate a fresh certificate for the ProxyAuth SSO identity.
    let userid = UserID::from("ProxyAuth <security@proxyauth.app>");
    let (cert, _) = CertBuilder::general_purpose([userid]).generate()?;

    // Encrypt every secret key (primary key + subkeys) with the
    // passphrase before it ever touches disk. This follows the
    // pattern documented in sequoia_openpgp::packet::key::Key::encrypt_secret.
    let mut encrypted_keys: Vec<Packet> = Vec::new();
    for ka in cert.keys().secret() {
        let key = ka.key().clone().encrypt_secret(&password)?;
        encrypted_keys.push(if ka.primary() {
            key.role_into_primary().into()
        } else {
            key.role_into_subordinate().into()
        });
    }

    // Merge the encrypted keys back into the certificate. Cert::insert_packets
    // prefers the newly added (encrypted) versions over the original
    // unencrypted ones.
    let cert = cert.insert_packets(encrypted_keys)?.0;

    let current = build_info::get();

    // Export the (now password-protected) private key to key.asc.
    let priv_path = format!("{}/key.asc", dir);
    let mut file = BufWriter::new(File::create(&priv_path)?);
    let mut armor = ArmorWriter::new(&mut file, ArmorKind::SecretKey)?;
    for pkt in cert.as_tsk().into_packets() {
        pkt.serialize(&mut armor)?;
    }
    armor.finalize()?;

    println!("Key export Success (secret key encrypted with AppConfig password)");

    // Encrypted message containing the current build info, used as a
    // sanity check / handshake payload for instances importing this key.
    let path_data = format!("{}/data.pgp", dir);
    let _ = encrypt(&cert, &current.to_string().as_str(), &path_data)?;

    Ok(())
}

/// Encrypts `text` to the given certificate's transport-encryption key
/// and writes the resulting OpenPGP message to `path`.
fn encrypt(cert: &Cert, text: &str, path: &str) -> anyhow::Result<()> {
    let policy = &StandardPolicy::new();

    let recipient_key = cert
    .keys()
    .with_policy(policy, None)
    .supported()
    .alive()
    .revoked(false)
    .for_transport_encryption()
    .next()
    .ok_or_else(|| anyhow::anyhow!("No suitable encryption key"))?;

    let file =
    File::create(path).with_context(|| format!("Failed to create output file: {}", path))?;
    let mut armor = ArmorWriter::new(file, ArmorKind::Message)?;

    let message = Message::new(&mut armor);

    let encryptor = Encryptor::for_recipients(message, [Recipient::from(recipient_key)]).build()?;

    // Write as a text literal for a valid GPG format.
    let mut literal = LiteralWriter::new(encryptor).build()?;
    literal.write_all(text.as_bytes())?;
    literal.finalize()?;

    armor.finalize()?;

    Ok(())
}
