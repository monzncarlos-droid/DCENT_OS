// SPDX-FileCopyrightText: 2026 D-Central Technologies <dev@d-central.tech>
// SPDX-License-Identifier: GPL-3.0-only
//!
//! A deliberately small detached-signature verifier for the S19k stage-1
//! transaction. The shell opens the request and signature once, performs all
//! parsing/hashing through those descriptors, and passes the same inherited
//! descriptors here. This avoids re-opening mutable pathnames at the final
//! authorization boundary.

#[cfg(any(unix, test))]
use ed25519_dalek::{Signature, VerifyingKey};
#[cfg(unix)]
use std::env;
#[cfg(any(unix, test))]
use std::fmt;
#[cfg(unix)]
use std::fs::File;
#[cfg(unix)]
use std::io::{Read, Seek, SeekFrom};

#[cfg(unix)]
use std::os::fd::{FromRawFd, RawFd};

#[cfg(any(unix, test))]
const MAX_MESSAGE_BYTES: usize = 32_768;
#[cfg(any(unix, test))]
const PUBLIC_KEY_BYTES: usize = 32;
#[cfg(any(unix, test))]
const SIGNATURE_BYTES: usize = 64;

const EXIT_INPUT: i32 = 2;
#[cfg(unix)]
const EXIT_SIGNATURE_INVALID: i32 = 3;

#[cfg(any(unix, test))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum VerifyError {
    PublicKeyEncoding,
    PublicKeyInvalid,
    MessageEmpty,
    MessageTooLarge,
    SignatureSize,
    SignatureInvalid,
}

#[cfg(any(unix, test))]
impl fmt::Display for VerifyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::PublicKeyEncoding => "public key must be exactly 64 lowercase hex characters",
            Self::PublicKeyInvalid => "public key is not a valid Ed25519 verifying key",
            Self::MessageEmpty => "message must not be empty",
            Self::MessageTooLarge => "message exceeds the 32768-byte limit",
            Self::SignatureSize => "signature must be exactly 64 bytes",
            Self::SignatureInvalid => "detached Ed25519 signature is invalid",
        };
        f.write_str(message)
    }
}

#[cfg(any(unix, test))]
fn decode_public_key(value: &str) -> Result<[u8; PUBLIC_KEY_BYTES], VerifyError> {
    if value.len() != PUBLIC_KEY_BYTES * 2
        || value
            .as_bytes()
            .iter()
            .any(|byte| !matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
    {
        return Err(VerifyError::PublicKeyEncoding);
    }

    let mut decoded = [0_u8; PUBLIC_KEY_BYTES];
    for (slot, pair) in decoded.iter_mut().zip(value.as_bytes().chunks_exact(2)) {
        let high = pair
            .first()
            .copied()
            .and_then(decode_nibble)
            .ok_or(VerifyError::PublicKeyEncoding)?;
        let low = pair
            .get(1)
            .copied()
            .and_then(decode_nibble)
            .ok_or(VerifyError::PublicKeyEncoding)?;
        *slot = (high << 4) | low;
    }
    Ok(decoded)
}

#[cfg(any(unix, test))]
fn decode_nibble(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        _ => None,
    }
}

#[cfg(any(unix, test))]
fn verify_bytes(
    public_key_hex: &str,
    message: &[u8],
    signature_bytes: &[u8],
) -> Result<(), VerifyError> {
    if message.is_empty() {
        return Err(VerifyError::MessageEmpty);
    }
    if message.len() > MAX_MESSAGE_BYTES {
        return Err(VerifyError::MessageTooLarge);
    }
    let signature_array: [u8; SIGNATURE_BYTES] = signature_bytes
        .try_into()
        .map_err(|_| VerifyError::SignatureSize)?;
    let public_key = VerifyingKey::from_bytes(&decode_public_key(public_key_hex)?)
        .map_err(|_| VerifyError::PublicKeyInvalid)?;
    let signature = Signature::from_bytes(&signature_array);
    public_key
        .verify_strict(message, &signature)
        .map_err(|_| VerifyError::SignatureInvalid)
}

#[cfg(unix)]
fn usage() -> &'static str {
    "usage: s19k-stage1-authorizer --public-key-hex <64-lower-hex> --message-fd <fd> --signature-fd <fd>"
}

#[cfg(unix)]
fn parse_fd(value: &str) -> Result<i32, &'static str> {
    let fd = value
        .parse::<i32>()
        .map_err(|_| "file descriptor is not an integer")?;
    if !(3..=1024).contains(&fd) {
        return Err("file descriptor must be between 3 and 1024");
    }
    Ok(fd)
}

#[cfg(unix)]
fn read_regular_fd(fd: RawFd, max_bytes: usize) -> Result<Vec<u8>, &'static str> {
    // SAFETY: the descriptor number is supplied by the trusted stage-1 shell,
    // range-checked above, and this short-lived process intentionally assumes
    // ownership of its inherited copy. No other Rust object owns it here.
    let mut file = unsafe { File::from_raw_fd(fd) };
    let metadata = file
        .metadata()
        .map_err(|_| "cannot stat inherited descriptor")?;
    if !metadata.is_file() {
        return Err("inherited descriptor is not a regular file");
    }
    file.seek(SeekFrom::Start(0))
        .map_err(|_| "cannot rewind inherited descriptor")?;
    let limit = u64::try_from(max_bytes)
        .map_err(|_| "invalid read limit")?
        .saturating_add(1);
    let mut bytes = Vec::with_capacity(max_bytes.min(4096));
    file.take(limit)
        .read_to_end(&mut bytes)
        .map_err(|_| "cannot read inherited descriptor")?;
    Ok(bytes)
}

#[cfg(unix)]
fn run() -> Result<(), (i32, String)> {
    let arguments: Vec<String> = env::args().collect();
    if arguments.len() != 7
        || arguments.get(1).map(String::as_str) != Some("--public-key-hex")
        || arguments.get(3).map(String::as_str) != Some("--message-fd")
        || arguments.get(5).map(String::as_str) != Some("--signature-fd")
    {
        return Err((EXIT_INPUT, usage().to_string()));
    }

    let public_key_hex = arguments
        .get(2)
        .ok_or_else(|| (EXIT_INPUT, usage().to_string()))?;
    decode_public_key(public_key_hex).map_err(|error| (EXIT_INPUT, error.to_string()))?;
    let message_fd = parse_fd(
        arguments
            .get(4)
            .ok_or_else(|| (EXIT_INPUT, usage().to_string()))?,
    )
    .map_err(|error| (EXIT_INPUT, error.to_string()))?;
    let signature_fd = parse_fd(
        arguments
            .get(6)
            .ok_or_else(|| (EXIT_INPUT, usage().to_string()))?,
    )
    .map_err(|error| (EXIT_INPUT, error.to_string()))?;
    if message_fd == signature_fd {
        return Err((
            EXIT_INPUT,
            "message and signature descriptors must be distinct".to_string(),
        ));
    }

    let message = read_regular_fd(message_fd, MAX_MESSAGE_BYTES)
        .map_err(|error| (EXIT_INPUT, error.to_string()))?;
    let signature = read_regular_fd(signature_fd, SIGNATURE_BYTES)
        .map_err(|error| (EXIT_INPUT, error.to_string()))?;
    verify_bytes(public_key_hex, &message, &signature).map_err(|error| {
        let exit = if error == VerifyError::SignatureInvalid {
            EXIT_SIGNATURE_INVALID
        } else {
            EXIT_INPUT
        };
        (exit, error.to_string())
    })
}

#[cfg(not(unix))]
fn run() -> Result<(), (i32, String)> {
    Err((
        EXIT_INPUT,
        "s19k-stage1-authorizer requires inherited Unix file descriptors".to_string(),
    ))
}

fn main() {
    if let Err((exit_code, message)) = run() {
        eprintln!("s19k-stage1-authorizer: {message}");
        std::process::exit(exit_code);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const RFC8032_PUBLIC_KEY: &str =
        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
    const RFC8032_EMPTY_SIGNATURE: [u8; 64] = [
        0xe5, 0x56, 0x43, 0x00, 0xc3, 0x60, 0xac, 0x72, 0x90, 0x86, 0xe2, 0xcc, 0x80, 0x6e, 0x82,
        0x8a, 0x84, 0x87, 0x7f, 0x1e, 0xb8, 0xe5, 0xd9, 0x74, 0xd8, 0x73, 0xe0, 0x65, 0x22, 0x49,
        0x01, 0x55, 0x5f, 0xb8, 0x82, 0x15, 0x90, 0xa3, 0x3b, 0xac, 0xc6, 0x1e, 0x39, 0x70, 0x1c,
        0xf9, 0xb4, 0x6b, 0xd2, 0x5b, 0xf5, 0xf0, 0x59, 0x5b, 0xbe, 0x24, 0x65, 0x51, 0x41, 0x43,
        0x8e, 0x7a, 0x10, 0x0b,
    ];
    // RFC 8032 test vector 2: a non-empty message, which matches the runtime
    // contract (stage-1 refuses an empty authorization request).
    const RFC8032_ONE_BYTE_PUBLIC_KEY: &str =
        "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c";
    const RFC8032_ONE_BYTE_SIGNATURE: [u8; 64] = [
        0x92, 0xa0, 0x09, 0xa9, 0xf0, 0xd4, 0xca, 0xb8, 0x72, 0x0e, 0x82, 0x0b, 0x5f, 0x64, 0x25,
        0x40, 0xa2, 0xb2, 0x7b, 0x54, 0x16, 0x50, 0x3f, 0x8f, 0xb3, 0x76, 0x22, 0x23, 0xeb, 0xdb,
        0x69, 0xda, 0x08, 0x5a, 0xc1, 0xe4, 0x3e, 0x15, 0x99, 0x6e, 0x45, 0x8f, 0x36, 0x13, 0xd0,
        0xf1, 0x1d, 0x8c, 0x38, 0x7b, 0x2e, 0xae, 0xb4, 0x30, 0x2a, 0xee, 0xb0, 0x0d, 0x29, 0x16,
        0x12, 0xbb, 0x0c, 0x00,
    ];

    #[test]
    fn accepts_rfc8032_non_empty_known_answer() {
        assert_eq!(
            verify_bytes(
                RFC8032_ONE_BYTE_PUBLIC_KEY,
                &[0x72],
                &RFC8032_ONE_BYTE_SIGNATURE,
            ),
            Ok(())
        );
    }

    #[test]
    fn rejects_tampered_message() {
        assert_eq!(
            verify_bytes(
                RFC8032_ONE_BYTE_PUBLIC_KEY,
                &[0x73],
                &RFC8032_ONE_BYTE_SIGNATURE,
            ),
            Err(VerifyError::SignatureInvalid)
        );
    }

    #[test]
    fn rejects_empty_message_even_when_signature_is_valid() {
        assert_eq!(
            verify_bytes(RFC8032_PUBLIC_KEY, &[], &RFC8032_EMPTY_SIGNATURE),
            Err(VerifyError::MessageEmpty)
        );
    }

    #[test]
    fn rejects_non_canonical_public_key_hex() {
        assert_eq!(
            decode_public_key("D75A980182B10AB7D54BFED3C964073A0EE172F3DAA62325AF021A68F707511A"),
            Err(VerifyError::PublicKeyEncoding)
        );
    }

    #[test]
    fn rejects_oversize_message_and_wrong_signature_size() {
        let oversize = vec![0_u8; MAX_MESSAGE_BYTES + 1];
        assert_eq!(
            verify_bytes(
                RFC8032_ONE_BYTE_PUBLIC_KEY,
                &oversize,
                &RFC8032_ONE_BYTE_SIGNATURE,
            ),
            Err(VerifyError::MessageTooLarge)
        );
        assert_eq!(
            verify_bytes(RFC8032_ONE_BYTE_PUBLIC_KEY, &[0x72], &[0_u8; 63]),
            Err(VerifyError::SignatureSize)
        );
    }
}
