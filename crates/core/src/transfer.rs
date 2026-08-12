use crate::PortablePack;
use age::{Decryptor, Encryptor, secrecy::SecretString};
use anyhow::{Context, Result, bail};
use std::io::{Read, Write};
use std::iter;
use zeroize::Zeroizing;

const MAX_PACK_BYTES: usize = 32 * 1024 * 1024;

pub fn encrypt_pack(pack: &PortablePack, passphrase: SecretString) -> Result<Vec<u8>> {
    let plain = Zeroizing::new(serde_json::to_vec(pack)?);
    if plain.len() > MAX_PACK_BYTES {
        bail!("pack exceeds maximum size");
    }
    let encryptor = Encryptor::with_user_passphrase(passphrase);
    let mut encrypted = Vec::new();
    let mut writer = encryptor.wrap_output(&mut encrypted)?;
    writer.write_all(&plain)?;
    writer.finish()?;
    Ok(encrypted)
}

pub fn decrypt_pack(input: &[u8], passphrase: SecretString) -> Result<PortablePack> {
    if input.len() > MAX_PACK_BYTES {
        bail!("encrypted pack exceeds maximum size");
    }
    let decryptor = Decryptor::new(input)?;
    let identity = age::scrypt::Identity::new(passphrase);
    let mut reader = decryptor.decrypt(iter::once(&identity as &dyn age::Identity))?;
    let mut plain = Zeroizing::new(Vec::new());
    reader
        .by_ref()
        .take((MAX_PACK_BYTES + 1) as u64)
        .read_to_end(&mut plain)?;
    if plain.len() > MAX_PACK_BYTES {
        bail!("decrypted pack exceeds maximum size");
    }
    let pack: PortablePack = serde_json::from_slice(&plain).context("invalid encrypted pack")?;
    if pack.format != "cargo-ai-pack" || pack.version != 2 || pack.contains_secrets {
        bail!("unsupported pack format or version");
    }
    Ok(pack)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::LocalProfile;
    use chrono::Utc;
    use uuid::Uuid;

    #[test]
    fn encrypted_pack_round_trip_and_wrong_password_fails() {
        let pack = PortablePack {
            format: "cargo-ai-pack".into(),
            version: 2,
            contains_secrets: false,
            exported_at: Utc::now(),
            profile: LocalProfile {
                id: Uuid::new_v4(),
                display_name: "Ada".into(),
                created_at: Utc::now(),
            },
            connections: vec![],
            memory: vec![],
        };
        let encrypted =
            encrypt_pack(&pack, SecretString::from("correct horse battery staple")).unwrap();
        assert!(!String::from_utf8_lossy(&encrypted).contains("Ada"));
        assert_eq!(
            decrypt_pack(
                &encrypted,
                SecretString::from("correct horse battery staple")
            )
            .unwrap()
            .profile
            .display_name,
            "Ada"
        );
        assert!(decrypt_pack(&encrypted, SecretString::from("wrong password")).is_err());
    }
}
