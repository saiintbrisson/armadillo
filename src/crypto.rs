use aes_gcm::aead::{Aead, KeyInit, OsRng};
use aes_gcm::{AeadCore, Aes256Gcm, Key, Nonce};
use anyhow::{Result, anyhow};
use pbkdf2::pbkdf2_hmac;
use regex::Regex;
use sha2::Sha256;
use std::path::Path;
use std::process::Command;
use std::sync::LazyLock;

static UUID_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})")
        .unwrap()
});

const SALT: &[u8] = b"HytaleAuthCredentialStore";
const ITERATIONS: u32 = 100_000;
const IV_LENGTH: usize = 12;

pub fn derive_key(hardware_uuid: &str) -> [u8; 32] {
    let mut key = [0u8; 32];
    pbkdf2_hmac::<Sha256>(hardware_uuid.as_bytes(), SALT, ITERATIONS, &mut key);
    key
}

pub fn decrypt_auth_file(encrypted: &[u8], hardware_uuid: &str) -> Result<String> {
    if encrypted.len() < IV_LENGTH {
        return Err(anyhow::anyhow!(
            "Encrypted data too short: {} bytes",
            encrypted.len()
        ));
    }

    let key_bytes = derive_key(hardware_uuid);
    let key = Key::<Aes256Gcm>::from_slice(&key_bytes);
    let cipher = Aes256Gcm::new(key);

    let nonce = Nonce::from_slice(&encrypted[..IV_LENGTH]);
    let ciphertext = &encrypted[IV_LENGTH..];

    let plaintext = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|e| anyhow::anyhow!("Decryption failed: {}", e))?;

    String::from_utf8(plaintext).map_err(|e| anyhow::anyhow!("Invalid UTF-8: {}", e))
}

pub fn encrypt_auth_file(plaintext: &[u8], hardware_uuid: &str) -> Result<Vec<u8>> {
    let key_bytes = derive_key(hardware_uuid);
    let key = Key::<Aes256Gcm>::from_slice(&key_bytes);
    let cipher = Aes256Gcm::new(key);
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);

    let ciphertext = cipher
        .encrypt(&nonce, plaintext)
        .map_err(|e| anyhow!("Encryption failed: {e}"))?;

    let mut result = Vec::with_capacity(IV_LENGTH + ciphertext.len());
    result.extend_from_slice(&nonce);
    result.extend_from_slice(&ciphertext);
    Ok(result)
}

fn serialize_credentials(creds: &AuthCredentials) -> Vec<u8> {
    let mut buf = Vec::new();

    // 4-byte header (observed in original format)
    buf.extend_from_slice(&[0u8; 4]);

    let fields = [
        ("AccessToken", &creds.access_token),
        ("RefreshToken", &creds.refresh_token),
        ("ExpiresAt", &creds.expires_at),
        ("ProfileUuid", &creds.profile_uuid),
    ];

    for (key, value) in fields {
        buf.push(0); // field separator
        buf.extend_from_slice(key.as_bytes());
        buf.push(0); // null terminator for key
        buf.extend_from_slice(&(value.len() as u32).to_le_bytes());
        buf.extend_from_slice(value.as_bytes());
    }

    buf
}

pub fn save_credentials_to_file(
    path: &Path,
    creds: &AuthCredentials,
    machine_id: Option<&str>,
) -> Result<()> {
    let hardware_uuid = match machine_id {
        Some(id) => id.to_string(),
        None => get_hardware_uuid()?,
    };

    let plaintext = serialize_credentials(creds);
    let encrypted = encrypt_auth_file(&plaintext, &hardware_uuid)?;
    std::fs::write(path, encrypted)?;

    tracing::debug!("Saved credentials to {}", path.display());
    Ok(())
}

pub fn get_hardware_uuid() -> Result<String> {
    #[cfg(target_os = "macos")]
    {
        if let Ok(output) = Command::new("/usr/sbin/ioreg")
            .args(["-rd1", "-c", "IOPlatformExpertDevice"])
            .output()
        {
            let stdout = String::from_utf8_lossy(&output.stdout);
            if let Some(uuid) = extract_uuid_from_text(&stdout, "IOPlatformUUID") {
                return Ok(uuid);
            }
        }

        if let Ok(output) = Command::new("/usr/sbin/system_profiler")
            .arg("SPHardwareDataType")
            .output()
        {
            let stdout = String::from_utf8_lossy(&output.stdout);
            if let Some(uuid) = extract_uuid_from_text(&stdout, "Hardware UUID") {
                return Ok(uuid);
            }
        }

        Err(anyhow!("Failed to get hardware UUID for macOS"))
    }

    #[cfg(target_os = "windows")]
    {
        if let Ok(output) = Command::new("reg")
            .args([
                "query",
                "HKLM\\SOFTWARE\\Microsoft\\Cryptography",
                "/v",
                "MachineGuid",
            ])
            .output()
        {
            let stdout = String::from_utf8_lossy(&output.stdout);
            if let Some(uuid) = extract_uuid_from_text(&stdout, "MachineGuid") {
                return Ok(uuid);
            }
        }

        if let Ok(output) = Command::new("powershell")
            .args([
                "-NoProfile",
                "-Command",
                "(Get-CimInstance -Class Win32_ComputerSystemProduct).UUID",
            ])
            .output()
        {
            let stdout = String::from_utf8_lossy(&output.stdout);
            if let Some(uuid) = extract_uuid_from_line(&stdout) {
                return Ok(uuid);
            }
        }

        if let Ok(output) = Command::new("wmic")
            .args(["csproduct", "get", "UUID"])
            .output()
        {
            let stdout = String::from_utf8_lossy(&output.stdout);
            if let Some(uuid) = extract_uuid_from_line(&stdout) {
                return Ok(uuid);
            }
        }

        Err(anyhow!("Failed to get hardware UUID for Windows"))
    }

    #[cfg(target_os = "linux")]
    {
        if let Ok(content) = std::fs::read_to_string("/etc/machine-id")
            && let Some(uuid) = parse_machine_id(&content)
        {
            return Ok(uuid);
        }

        if let Ok(content) = std::fs::read_to_string("/var/lib/dbus/machine-id")
            && let Some(uuid) = parse_machine_id(&content)
        {
            return Ok(uuid);
        }

        if let Ok(content) = std::fs::read_to_string("/sys/class/dmi/id/product_uuid")
            && let Some(uuid) = extract_uuid_from_line(&content)
        {
            return Ok(uuid);
        }

        if let Ok(output) = Command::new("dmidecode")
            .args(["-s", "system-uuid"])
            .output()
        {
            let stdout = String::from_utf8_lossy(&output.stdout);
            if let Some(uuid) = extract_uuid_from_line(&stdout) {
                return Ok(uuid);
            }
        }

        Err(anyhow!("Failed to get hardware UUID for Linux"))
    }

    #[cfg(not(any(target_os = "windows", target_os = "macos", target_os = "linux")))]
    {
        Err(anyhow!("Unsupported platform for hardware UUID detection"))
    }
}

#[cfg(any(target_os = "windows", target_os = "macos"))]
fn extract_uuid_from_text(text: &str, key: &str) -> Option<String> {
    for line in text.lines() {
        if line.contains(key)
            && let Some(uuid) = extract_uuid_from_line(line)
        {
            return Some(uuid);
        }
    }
    None
}

fn extract_uuid_from_line(line: &str) -> Option<String> {
    UUID_REGEX
        .captures(line)
        .and_then(|cap| cap.get(1).map(|m| m.as_str().to_lowercase()))
}

#[cfg(target_os = "linux")]
fn parse_machine_id(content: &str) -> Option<String> {
    let hex = content.trim();
    if hex.len() == 32 {
        Some(
            format!(
                "{}-{}-{}-{}-{}",
                &hex[0..8],
                &hex[8..12],
                &hex[12..16],
                &hex[16..20],
                &hex[20..32]
            )
            .to_lowercase(),
        )
    } else {
        None
    }
}

#[derive(Debug, Clone)]
pub struct AuthCredentials {
    pub access_token: String,
    pub refresh_token: String,
    pub expires_at: String,
    pub profile_uuid: String,
}

pub fn load_credentials_from_file(
    data: &[u8],
    machine_id: Option<&str>,
) -> Result<AuthCredentials> {
    let hardware_uuid = match machine_id {
        Some(id) => id.to_string(),
        None => get_hardware_uuid()?,
    };
    tracing::debug!("Using hardware UUID: {hardware_uuid}");
    let decrypted = decrypt_auth_file(data, &hardware_uuid)?;
    parse_auth_credentials(decrypted.as_bytes())
}

fn parse_auth_credentials(data: &[u8]) -> Result<AuthCredentials> {
    let mut pos = 4;
    let mut access_token = None;
    let mut refresh_token = None;
    let mut expires_at = None;
    let mut profile_uuid = None;

    while pos < data.len() {
        if pos >= data.len() {
            break;
        }
        pos += 1;

        let key_start = pos;
        while pos < data.len() && data[pos] != 0 {
            pos += 1;
        }
        let key = std::str::from_utf8(&data[key_start..pos])
            .map_err(|e| anyhow!("Invalid key UTF-8: {e}"))?;
        pos += 1;

        if pos + 4 > data.len() {
            break;
        }
        let value_len =
            u32::from_le_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]]) as usize;
        pos += 4;

        if pos + value_len > data.len() {
            break;
        }
        let value_bytes = &data[pos..pos + value_len];

        let value_end = value_bytes
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(value_bytes.len());
        let value = std::str::from_utf8(&value_bytes[..value_end])
            .map_err(|e| anyhow!("Invalid value UTF-8 for {key}: {e}"))?;
        pos += value_len;

        match key {
            "AccessToken" => access_token = Some(value.to_string()),
            "RefreshToken" => refresh_token = Some(value.to_string()),
            "ExpiresAt" => expires_at = Some(value.to_string()),
            "ProfileUuid" => profile_uuid = Some(value.to_string()),
            _ => {}
        }
    }

    Ok(AuthCredentials {
        access_token: access_token.ok_or_else(|| anyhow!("Missing AccessToken"))?,
        refresh_token: refresh_token.ok_or_else(|| anyhow!("Missing RefreshToken"))?,
        expires_at: expires_at.ok_or_else(|| anyhow!("Missing ExpiresAt"))?,
        profile_uuid: profile_uuid.ok_or_else(|| anyhow!("Missing ProfileUuid"))?,
    })
}
