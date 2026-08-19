use crate::smtp::smtp::RESET_TEMPLATE_PATH;
use std::fs;
use std::io::Write;
use std::path::Path;

pub fn ensure_reset_template_exists() -> std::io::Result<()> {
    let path = Path::new(RESET_TEMPLATE_PATH);

    if !path.exists() {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }

        let default_template = r#"Subject = "ProxyAuth Password Reset"

        Hello {{ username }},

        A password reset request has been initiated for your account.

        Click the link below to set a new password:
        {{ reset_link }}

        This link is valid for a limited time.

        If you did not request this, simply ignore this message.

        —
        ProxyAuth Security System
        "#;

        let mut file = fs::File::create(path)?;
        file.write_all(default_template.as_bytes())?;
        println!("Reset password template created at {}", RESET_TEMPLATE_PATH);
    }

    Ok(())
}
