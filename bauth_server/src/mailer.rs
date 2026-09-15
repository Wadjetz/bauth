use lettre::message::Mailbox;
use lettre::message::header::ContentType;
use lettre::{AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor};

#[derive(Debug, thiserror::Error)]
pub enum MailError {
    #[error("invalid address: {0}")]
    Address(#[from] lettre::address::AddressError),
    #[error("invalid message: {0}")]
    Message(#[from] lettre::error::Error),
    #[error("smtp error: {0}")]
    Smtp(#[from] lettre::transport::smtp::Error),
}

#[derive(Debug, Clone)]
pub struct Email {
    pub to: String,
    pub subject: String,
    pub text: String,
}

#[derive(Clone)]
pub struct Mailer {
    transport: Transport,
    from: Mailbox,
}

#[derive(Clone)]
enum Transport {
    Smtp(AsyncSmtpTransport<Tokio1Executor>),
    /// Tests: keeps emails in memory instead of sending them.
    #[cfg(test)]
    Capture(std::sync::Arc<std::sync::Mutex<Vec<Email>>>),
}

impl Mailer {
    /// `smtp_url`: `smtp://localhost:1025` in dev, `smtps://user:pass@host:465` in prod.
    pub fn new(smtp_url: &str, from: &str) -> Result<Self, MailError> {
        let from = from.parse()?;
        let transport = AsyncSmtpTransport::<Tokio1Executor>::from_url(smtp_url)?.build();
        Ok(Self {
            transport: Transport::Smtp(transport),
            from,
        })
    }

    /// A mailer recording emails, and the list it records them in.
    #[cfg(test)]
    pub fn capture() -> (Self, std::sync::Arc<std::sync::Mutex<Vec<Email>>>) {
        let outbox = std::sync::Arc::default();
        let mailer = Self {
            transport: Transport::Capture(std::sync::Arc::clone(&outbox)),
            from: "bauth <no-reply@example.com>"
                .parse()
                .expect("valid sender"),
        };
        (mailer, outbox)
    }

    fn message(&self, email: Email) -> Result<Message, MailError> {
        Ok(Message::builder()
            .from(self.from.clone())
            .to(email.to.parse()?)
            .subject(email.subject)
            .header(ContentType::TEXT_PLAIN)
            .body(email.text)?)
    }

    pub async fn send(&self, email: Email) -> Result<(), MailError> {
        match &self.transport {
            Transport::Smtp(transport) => {
                transport.send(self.message(email)?).await?;
            }
            #[cfg(test)]
            Transport::Capture(outbox) => {
                // Build the real message anyway, so tests catch invalid emails.
                self.message(email.clone())?;
                outbox.lock().unwrap().push(email);
            }
        }
        Ok(())
    }

    /// SMTP can take seconds: don't make the client wait, and don't let the delay reveal
    /// which branch of a handler ran. Failures are only logged.
    pub fn send_in_background(&self, email: Email) {
        // Recorded right away, so a test sees the email as soon as the request returns.
        #[cfg(test)]
        if let Transport::Capture(outbox) = &self.transport {
            self.message(email.clone()).expect("valid email");
            outbox.lock().unwrap().push(email);
            return;
        }
        let mailer = self.clone();
        tokio::spawn(async move {
            if let Err(error) = mailer.send(email).await {
                tracing::error!(%error, "failed to send email");
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn rejects_invalid_sender() {
        assert!(Mailer::new("smtp://localhost:1025", "not an address").is_err());
    }

    #[tokio::test]
    async fn builds_utf8_plain_text_messages() {
        let mailer = Mailer::new("smtp://localhost:1025", "bauth <no-reply@example.com>").unwrap();
        let email = Email {
            to: "alice@example.com".into(),
            subject: "Confirme ton adresse email à My App".into(),
            text: "Ce lien expire dans 24 heures.".into(),
        };
        let raw = String::from_utf8(mailer.message(email.clone()).unwrap().formatted()).unwrap();

        assert!(raw.contains("From: bauth <no-reply@example.com>"), "{raw}");
        assert!(raw.contains("To: alice@example.com"), "{raw}");
        assert!(
            raw.contains("Content-Type: text/plain; charset=utf-8"),
            "{raw}"
        );
        // Headers must be ASCII: the accented subject word is MIME-encoded.
        let headers = raw.split("\r\n\r\n").next().unwrap();
        assert!(headers.is_ascii(), "{headers}");
        assert!(headers.contains("=?utf-8?b?"), "{headers}");

        let invalid = Email {
            to: "not an address".into(),
            ..email
        };
        assert!(matches!(
            mailer.message(invalid),
            Err(MailError::Address(_))
        ));
    }
}
