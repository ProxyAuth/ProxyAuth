use lettre::{
    message::header::ContentType,
    transport::smtp::authentication::Credentials,
    AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor,
};
use serde::{Deserialize, Serialize};
use std::time::Duration;
use std::fs;

pub const RESET_TEMPLATE_PATH: &str = "/etc/proxyauth/mail/reset_password.txt";

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SmtpConfig {
    pub host: String,
    pub port: u16,
    pub username: String,
    pub password: String,
    pub from: String,
    pub timeout_secs: u64,
}

#[allow(dead_code)]
pub struct ResetTemplate {
    pub subject: String,
    pub body: String,
}

#[allow(dead_code)]
pub struct SmtpClient {
    mailer: AsyncSmtpTransport<Tokio1Executor>,
    from: String,
    reset_template: ResetTemplate,
}

#[allow(dead_code)]
impl SmtpClient {
    pub fn new(cfg: &SmtpConfig) -> Result<Self, Box<dyn std::error::Error>> {
        let creds = Credentials::new(cfg.username.clone(), cfg.password.clone());

        let builder = if cfg.port == 465 {
            AsyncSmtpTransport::<Tokio1Executor>::relay(&cfg.host)?
            .port(cfg.port)
        } else {
            AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(&cfg.host)?
            .port(cfg.port)
        };

        let mailer = builder
        .credentials(creds)
        .timeout(Some(Duration::from_secs(cfg.timeout_secs)))
        .build();

        // Load + parse reset template
        let raw = fs::read_to_string(RESET_TEMPLATE_PATH)
        .map_err(|e| format!(
            "Failed to read reset password template at {}: {}",
            RESET_TEMPLATE_PATH, e
        ))?;

        let reset_template = Self::parse_reset_template(&raw)?;

        Ok(Self {
            mailer,
            from: cfg.from.clone(),
           reset_template,
        })
    }

    /// Parse template
    /// - extract Subject = "..."
    /// - remove this line from body
    fn parse_reset_template(raw: &str) -> Result<ResetTemplate, Box<dyn std::error::Error>> {
        let mut lines = raw.lines();

        let first_line = lines.next().ok_or("Reset password template is empty")?;

        let subject = if let Some(rest) = first_line.strip_prefix("Subject = ") {
            let trimmed = rest.trim();

            if trimmed.starts_with('"') && trimmed.ends_with('"') {
                trimmed.trim_matches('"').to_string()
            } else {
                return Err("Subject line must be enclosed in double quotes".into());
            }
        } else {
            return Err("First line of reset template must start with: Subject = \"...\"".into());
        };

        let body = lines.collect::<Vec<_>>().join("\n");

        Ok(ResetTemplate { subject, body })
    }

    async fn send_text(
        &self,
        to: &str,
        subject: &str,
        body: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {

        let email = Message::builder()
        .from(self.from.parse().map_err(|e| format!("Invalid From address: {}", e))?)
        .to(to.parse().map_err(|e| format!("Invalid To address '{}': {}", to, e))?)
        .subject(subject)
        .header(ContentType::TEXT_PLAIN)
        .body(body.to_string())?;

        self.mailer.send(email)
        .await
        .map(|_response| ())
        .map_err(|e| format!("Failed to send email via SMTP: {}", e).into())
    }

    fn render_reset_body(&self, username: &str, reset_link: &str) -> String {
        self.reset_template
        .body
        .replace("{{ username }}", username)
        .replace("{{ reset_link }}", reset_link)
    }

    pub async fn send_reset_password(
        &self,
        to: &str,
        username: &str,
        reset_link: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {

        let body = self.render_reset_body(username, reset_link);

        self.send_text(
            to,
            &self.reset_template.subject,
            &body,
        ).await
    }
}
