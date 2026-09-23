//! Every email bauth sends. Each one is a pair of Tera templates in `templates/emails/`: `.txt`
//! (text-only clients, and what tests read) and `.html` (code in bold, clickable link), sharing
//! `base.*` and the `components.html` components. They are compiled into the binary. `.html`
//! templates escape every value; `.txt` ones don't need to.

use std::sync::LazyLock;

use tera::Context;
use tera::Tera;

use crate::mailer::Email;

macro_rules! templates {
    ($($name:literal),* $(,)?) => {
        [$(($name, include_str!(concat!("../templates/emails/", $name)))),*]
    };
}

static TEMPLATES: LazyLock<Tera> = LazyLock::new(|| {
    let mut tera = Tera::new();
    tera.add_raw_templates(templates![
        "components.html",
        "base.html",
        "base.txt",
        "verify_email.html",
        "verify_email.txt",
        "account_already_exists.html",
        "account_already_exists.txt",
        "password_reset.html",
        "password_reset.txt",
        "password_changed.html",
        "password_changed.txt",
        "magic_link.html",
        "magic_link.txt",
        "unverified_password_removed.html",
        "unverified_password_removed.txt",
        "confirm_email_change.html",
        "confirm_email_change.txt",
        "email_changed.html",
        "email_changed.txt",
        "account_deleted.html",
        "account_deleted.txt",
    ])
    .expect("email templates are valid (checked by tests)");
    tera
});

/// Renders `<template>.txt` and `<template>.html` with `context` (plus `subject`).
fn render(to: &str, subject: String, template: &str, mut context: Context) -> Email {
    context.insert("subject", &subject);
    let render = |extension: &str| {
        TEMPLATES
            .render(&format!("{template}.{extension}"), &context)
            .unwrap_or_else(|error| panic!("email template {template}.{extension}: {error}"))
    };
    let text = render("txt");
    Email {
        to: to.to_owned(),
        subject,
        text: format!("{}\n", text.trim_end()),
        html: render("html"),
    }
}

pub fn verify_email(to: &str, link: &str) -> Email {
    let mut context = Context::new();
    context.insert("link", link);
    render(
        to,
        "Confirmez votre adresse email".to_owned(),
        "verify_email",
        context,
    )
}

/// Sent when someone registers with an address that already has an account.
pub fn account_already_exists(to: &str) -> Email {
    render(
        to,
        "Tentative d'inscription avec votre adresse email".to_owned(),
        "account_already_exists",
        Context::new(),
    )
}

pub fn password_reset(to: &str, app_name: &str, link: &str) -> Email {
    let mut context = Context::new();
    context.insert("app_name", app_name);
    context.insert("link", link);
    render(
        to,
        format!("Réinitialisez votre mot de passe {app_name}"),
        "password_reset",
        context,
    )
}

/// Sent after a reset, so the owner notices if they weren't the one who did it.
pub fn password_changed(to: &str) -> Email {
    render(
        to,
        "Votre mot de passe a été modifié".to_owned(),
        "password_changed",
        Context::new(),
    )
}

/// The code is for another device than the mailbox's: mobile mail apps open links elsewhere.
pub fn magic_link(to: &str, app_name: &str, link: &str, code: &str) -> Email {
    magic(
        to,
        format!("Votre lien de connexion à {app_name}"),
        app_name,
        link,
        code,
        false,
    )
}

/// A magic link email to an address without an account: using the code or link creates it.
pub fn magic_signup(to: &str, app_name: &str, link: &str, code: &str) -> Email {
    magic(
        to,
        format!("Créez votre compte {app_name}"),
        app_name,
        link,
        code,
        true,
    )
}

fn magic(to: &str, subject: String, app_name: &str, link: &str, code: &str, signup: bool) -> Email {
    let mut context = Context::new();
    context.insert("app_name", app_name);
    context.insert("link", link);
    context.insert("code", code);
    context.insert("signup", &signup);
    render(to, subject, "magic_link", context)
}

/// Sent when a magic link login verifies an account whose password was set before its address
/// was confirmed: whoever registered may not be the owner.
pub fn unverified_password_removed(to: &str) -> Email {
    render(
        to,
        "Le mot de passe de votre compte a été supprimé".to_owned(),
        "unverified_password_removed",
        Context::new(),
    )
}

/// Sent to the new address: clicking the link proves the user owns it.
pub fn confirm_email_change(to: &str, link: &str) -> Email {
    let mut context = Context::new();
    context.insert("link", link);
    render(
        to,
        "Confirmez votre nouvelle adresse email".to_owned(),
        "confirm_email_change",
        context,
    )
}

/// Sent to the old address once the change is done, so its owner notices a takeover.
pub fn email_changed(to: &str, new_email: &str) -> Email {
    let mut context = Context::new();
    context.insert("new_email", new_email);
    render(
        to,
        "Votre adresse email a été modifiée".to_owned(),
        "email_changed",
        context,
    )
}

pub fn account_deleted(to: &str) -> Email {
    render(
        to,
        "Votre compte a été supprimé".to_owned(),
        "account_deleted",
        Context::new(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    const LINK: &str = "https://app.example.com/magic#token=abc";

    fn all() -> Vec<Email> {
        vec![
            verify_email("a@b.fr", LINK),
            account_already_exists("a@b.fr"),
            password_reset("a@b.fr", "App", LINK),
            password_changed("a@b.fr"),
            magic_link("a@b.fr", "App", LINK, "042917"),
            magic_signup("a@b.fr", "App", LINK, "042917"),
            unverified_password_removed("a@b.fr"),
            confirm_email_change("a@b.fr", LINK),
            email_changed("a@b.fr", "c@d.fr"),
            account_deleted("a@b.fr"),
        ]
    }

    #[test]
    fn every_template_renders_both_parts() {
        for email in all() {
            assert!(email.text.starts_with("Bonjour,\n\n"), "{}", email.text);
            assert!(
                !email.text.contains("{{") && !email.text.contains('<'),
                "{}",
                email.text
            );
            assert!(!email.text.contains("\n\n\n"), "{}", email.text);
            assert!(email.html.contains("<title>"), "{}", email.subject);
            assert!(!email.html.contains("{{"), "{}", email.html);
        }
    }

    #[test]
    fn text_keeps_the_code_and_url_on_their_own_lines() {
        let email = magic_link("a@b.fr", "My App", LINK, "042917");
        let lines: Vec<&str> = email.text.lines().collect();
        assert!(lines.contains(&"042917"), "{}", email.text);
        assert!(lines.contains(&LINK), "{}", email.text);
    }

    #[test]
    fn html_has_a_bold_code_and_a_real_link() {
        let login = magic_link("a@b.fr", "My App", LINK, "042917");
        assert!(
            login.html.contains("<strong>042917</strong>"),
            "{}",
            login.html
        );
        assert!(
            login.html.contains(&format!("<a href=\"{LINK}\"")),
            "{}",
            login.html
        );
        assert!(login.html.contains("Me connecter"));
        let signup = magic_signup("a@b.fr", "My App", LINK, "042917");
        assert!(signup.html.contains("Créer mon compte"), "{}", signup.html);
    }

    #[test]
    fn html_escapes_values() {
        let email = magic_link(
            "a@b.fr",
            "<b>Evil</b> & co",
            "https://app.example.com/?a=1&b=\"2\"",
            "042917",
        );
        assert!(!email.html.contains("<b>Evil"), "{}", email.html);
        assert!(email.html.contains("&lt;b&gt;Evil&lt;"), "{}", email.html);
        assert!(!email.html.contains("b=\"2\""), "{}", email.html);
        // The text part is plain: nothing to escape.
        assert!(email.text.contains("<b>Evil</b> & co"));
    }

    #[test]
    fn emails_use_vous() {
        for email in all() {
            let words = format!("{} {}", email.subject, email.text).to_lowercase();
            for tu in [" tu ", " ton ", " ta ", " tes ", " toi", "-toi", "-le "] {
                assert!(!words.contains(tu), "`{tu}` in: {words}");
            }
        }
    }
}
