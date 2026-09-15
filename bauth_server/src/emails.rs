use crate::mailer::Email;

pub fn verify_email(to: &str, link: &str) -> Email {
    Email {
        to: to.to_owned(),
        subject: "Confirme ton adresse email".to_owned(),
        text: format!(
            "Bonjour,\n\n\
             Pour activer ton compte, confirme ton adresse email en ouvrant ce lien :\n\n\
             {link}\n\n\
             Ce lien expire dans 24 heures.\n\
             Si tu n'as pas créé de compte, ignore cet email.\n"
        ),
    }
}

/// Sent when someone registers with an address that already has an account.
pub fn account_already_exists(to: &str) -> Email {
    Email {
        to: to.to_owned(),
        subject: "Tentative d'inscription avec ton adresse email".to_owned(),
        text: "Bonjour,\n\n\
               Quelqu'un a essayé de créer un compte avec ton adresse email, \
               mais tu en as déjà un.\n\n\
               Si c'était toi, connecte-toi, ou réinitialise ton mot de passe si tu l'as oublié.\n\
               Sinon, tu peux ignorer cet email : ton compte n'a pas été modifié.\n"
            .to_owned(),
    }
}

pub fn password_reset(to: &str, app_name: &str, link: &str) -> Email {
    Email {
        to: to.to_owned(),
        subject: format!("Réinitialise ton mot de passe {app_name}"),
        text: format!(
            "Bonjour,\n\n\
             Tu as demandé à réinitialiser ton mot de passe {app_name}. Ouvre ce lien pour en choisir un nouveau :\n\n\
             {link}\n\n\
             Ce lien expire dans 30 minutes et ne fonctionne qu'une fois.\n\
             Si tu n'es pas à l'origine de cette demande, ignore cet email : ton mot de passe ne change pas.\n"
        ),
    }
}

/// Sent after a reset, so the owner notices if they weren't the one who did it.
pub fn password_changed(to: &str) -> Email {
    Email {
        to: to.to_owned(),
        subject: "Ton mot de passe a été modifié".to_owned(),
        text: "Bonjour,\n\n\
               Le mot de passe de ton compte vient d'être modifié, et tes autres appareils ont été déconnectés.\n\n\
               Si c'était toi, tu n'as rien à faire.\n\
               Sinon, réinitialise ton mot de passe tout de suite depuis l'écran de connexion.\n"
            .to_owned(),
    }
}

/// The code is for another device than the mailbox's: mobile mail apps open links elsewhere.
pub fn magic_link(to: &str, app_name: &str, link: &str, code: &str) -> Email {
    Email {
        to: to.to_owned(),
        subject: format!("Ton lien de connexion à {app_name}"),
        text: format!(
            "Bonjour,\n\n\
             Pour te connecter à {app_name}, saisis ce code sur l'appareil où tu as demandé la connexion :\n\n\
             {code}\n\n\
             Ou ouvre ce lien sur cet appareil :\n\n\
             {link}\n\n\
             Le code et le lien expirent dans 15 minutes et ne servent qu'une fois.\n\
             Ne communique ce code à personne.\n\
             Si tu n'as pas demandé à te connecter, ignore cet email.\n"
        ),
    }
}

/// A magic link email to an address without an account: using the code or link creates it.
pub fn magic_signup(to: &str, app_name: &str, link: &str, code: &str) -> Email {
    Email {
        to: to.to_owned(),
        subject: format!("Crée ton compte {app_name}"),
        text: format!(
            "Bonjour,\n\n\
             Pour créer ton compte {app_name}, saisis ce code sur l'appareil où tu l'as demandé :\n\n\
             {code}\n\n\
             Ou ouvre ce lien sur cet appareil :\n\n\
             {link}\n\n\
             Le code et le lien expirent dans 15 minutes et ne servent qu'une fois.\n\
             Ne communique ce code à personne.\n\
             Si tu n'as rien demandé, ignore cet email : aucun compte ne sera créé.\n"
        ),
    }
}

/// Sent when a magic link login verifies an account whose password was set before its address
/// was confirmed: whoever registered may not be the owner.
pub fn unverified_password_removed(to: &str) -> Email {
    Email {
        to: to.to_owned(),
        subject: "Le mot de passe de ton compte a été supprimé".to_owned(),
        text: "Bonjour,\n\n\
               Tu viens de te connecter par email à un compte dont l'adresse n'avait pas encore été confirmée.\n\
               Par sécurité, le mot de passe défini à sa création a été supprimé : \
               n'importe qui peut créer un compte avec une adresse qui n'est pas la sienne.\n\n\
               Pour te connecter avec un mot de passe, choisis-en un avec « Mot de passe oublié ».\n"
            .to_owned(),
    }
}

/// Sent to the new address: clicking the link proves the user owns it.
pub fn confirm_email_change(to: &str, link: &str) -> Email {
    Email {
        to: to.to_owned(),
        subject: "Confirme ta nouvelle adresse email".to_owned(),
        text: format!(
            "Bonjour,\n\n\
             Pour utiliser cette adresse avec ton compte, confirme-la en ouvrant ce lien :\n\n\
             {link}\n\n\
             Ce lien expire dans 1 heure.\n\
             Si tu n'as rien demandé, ignore cet email : aucun compte ne sera modifié.\n"
        ),
    }
}

/// Sent to the old address once the change is done, so its owner notices a takeover.
pub fn email_changed(to: &str, new_email: &str) -> Email {
    Email {
        to: to.to_owned(),
        subject: "Ton adresse email a été modifiée".to_owned(),
        text: format!(
            "Bonjour,\n\n\
             L'adresse email de ton compte est maintenant {new_email}.\n\n\
             Si ce n'est pas toi, ton compte est peut-être compromis : contacte-nous en répondant à cet email.\n"
        ),
    }
}

pub fn account_deleted(to: &str) -> Email {
    Email {
        to: to.to_owned(),
        subject: "Ton compte a été supprimé".to_owned(),
        text: "Bonjour,\n\n\
               Ton compte et toutes tes sessions ont été supprimés.\n\
               Si ce n'est pas toi, contacte-nous en répondant à cet email.\n"
            .to_owned(),
    }
}
