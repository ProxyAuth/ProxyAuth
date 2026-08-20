use crate::smtp::smtp::RESET_TEMPLATE_PATH;
use std::fs;
use std::io::Write;
use std::path::Path;

/// Creates `/etc/proxyauth/mail/templates/reset_password.txt` (and the
/// `templates/` directory, if missing) with a sane default, but only
/// if it doesn't already exist — never overwrites a template an
/// operator has customized. One file per email purpose lives under
/// this directory (`{{ ... }}` placeholders are substituted at send
/// time); `reset_password.txt` is the only one ProxyAuth currently
/// sends, but the directory is organized to hold more as new email
/// flows are added, without every template competing for the same
/// flat `mail/` folder.
pub fn ensure_reset_template_exists() -> std::io::Result<()> {
    let path = Path::new(RESET_TEMPLATE_PATH);

    if !path.exists() {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }

        // Explicit "\n"-joined lines, not an indented raw string block —
        // a raw string literal indented to match the surrounding Rust
        // code would embed that same indentation into every line of
        // the actual email body sent to users.
        let default_template = concat!(
            "Subject = \"ProxyAuth Password Reset\"\n",
            "Hello {{ username }},\n",
            "\n",
            "A password reset request has been initiated for your account.\n",
            "\n",
            "Click the link below to set a new password:\n",
            "{{ reset_link }}\n",
            "\n",
            "This link is valid for a limited time.\n",
            "\n",
            "If you did not request this, simply ignore this message — your\n",
            "current password will keep working.\n",
            "\n",
            "—\n",
            "ProxyAuth Security System\n",
        );

        let mut file = fs::File::create(path)?;
        file.write_all(default_template.as_bytes())?;
        println!("Reset password template created at {}", RESET_TEMPLATE_PATH);
    }

    Ok(())
}
