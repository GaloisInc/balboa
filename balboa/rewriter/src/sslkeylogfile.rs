//! Module for accessing the SSL key log file.

use crate::{tls, tls_rewriter::TlsSecretProvider};
use hex::FromHex;
use parking_lot::{Condvar, Mutex, RwLock};
use stallone::LoggableMetadata;
use std::{collections::HashMap, fs::File, io::Read, path::Path, sync::Arc};

struct MasterSecretFuture {
    mutex: Mutex<Option<tls::TlsSecret>>,
    cond_var: Condvar,
}

impl MasterSecretFuture {
    fn new() -> MasterSecretFuture {
        MasterSecretFuture {
            mutex: Mutex::new(None),
            cond_var: Condvar::new(),
        }
    }

    fn populate(&self, value: tls::TlsSecret) {
        *self.mutex.lock() = Some(value);
        self.cond_var.notify_all();
    }

    fn join(&self) -> tls::TlsSecret {
        let mut guard = self.mutex.lock();
        while guard.is_none() {
            self.cond_var.wait(&mut guard);
        }
        guard.unwrap()
    }

    fn ask(&self) -> Option<tls::TlsSecret> {
        *self.mutex.lock()
    }
}

type SecretMapKey = (tls::TlsSecretLabel, tls::ClientRandom);

/// Struct encoding information found in the SSL key log file.
pub struct SSLKeyLogFile {
    // TODO: clear out entries when they're fetched.
    // TODO: to speed up the FIFO read, have an incremental buffer?
    master_secrets: RwLock<HashMap<SecretMapKey, Arc<MasterSecretFuture>>>,
}

#[derive(Debug, LoggableMetadata)]
pub struct Entry {
    pub key: SecretMapKey,
    pub master_secret: tls::TlsSecret,
}

pub fn parse_sslkeylogfile_entry(mut entry: &[u8]) -> Result<Option<Entry>, ()> {
    // SSLKEYLOGFILE entries for TLS 1.2
    const CLIENT_RANDOM_LABEL: &[u8] = b"CLIENT_RANDOM ";
    // SSLKEYLOGFILE entries for TLS 1.3
    const CLIENT_HANDSHAKE_TRAFFIC_SECRET_LABEL: &[u8] = b"CLIENT_HANDSHAKE_TRAFFIC_SECRET ";
    const SERVER_HANDSHAKE_TRAFFIC_SECRET_LABEL: &[u8] = b"SERVER_HANDSHAKE_TRAFFIC_SECRET ";
    const CLIENT_TRAFFIC_SECRET_0_LABEL: &[u8] = b"CLIENT_TRAFFIC_SECRET_0 ";
    const SERVER_TRAFFIC_SECRET_0_LABEL: &[u8] = b"SERVER_TRAFFIC_SECRET_0 ";

    const CLIENT_RANDOM_LEN: usize = 64;
    const SECRET_LEN_32B: usize = 64;
    const SECRET_LEN_48B: usize = 96;
    const SECRET_LEN_64B: usize = 128;

    fn parse_tls12_secret(payload: &[u8]) -> Option<&[u8]> {
        let label = CLIENT_RANDOM_LABEL;
        let expected_payload_len = label.len() + CLIENT_RANDOM_LEN + 1 + SECRET_LEN_48B;
        if payload.len() == expected_payload_len && payload.starts_with(label) {
            Some(&payload[label.len()..])
        } else {
            None
        }
    }

    fn parse_tls13_secret<'a>(payload: &'a [u8], label: &[u8]) -> Option<&'a [u8]> {
        // TLS 1.3 secrets can be one of three sizes
        let base_payload_len = label.len() + CLIENT_RANDOM_LEN + 1;
        let expected_payload_len_1 = base_payload_len + SECRET_LEN_32B;
        let expected_payload_len_2 = base_payload_len + SECRET_LEN_48B;
        let expected_payload_len_3 = base_payload_len + SECRET_LEN_64B;
        if (payload.len() == expected_payload_len_1
            || payload.len() == expected_payload_len_2
            || payload.len() == expected_payload_len_3)
            && payload.starts_with(label)
        {
            Some(&payload[label.len()..])
        } else {
            None
        }
    }

    fn decode_tls12_secret(secret_hex: &[u8]) -> Option<tls::MasterSecret12> {
        Some(tls::MasterSecret12(<_>::from_hex(secret_hex).ok()?))
    }

    fn decode_tls13_secret(secret_hex: &[u8]) -> Option<tls::Tls13Secret> {
        match secret_hex.len() {
            SECRET_LEN_32B => Some(tls::Tls13Secret::B32(<_>::from_hex(secret_hex).ok()?)),
            SECRET_LEN_48B => Some(tls::Tls13Secret::B48(<_>::from_hex(secret_hex).ok()?)),
            SECRET_LEN_64B => Some(tls::Tls13Secret::B64(<_>::from_hex(secret_hex).ok()?)),
            x => {
                stallone::error!(
                    "This case should be unreachable, there's a bug in the secret-parsing code",
                    secret_hex: &[u8] = secret_hex,
                    secret_hex_len: usize = x,
                );
                None
            }
        }
    }

    if entry.starts_with(b"#") {
        // Technically comments are allowed.
        return Ok(None);
    }
    while let Some(b'\n') = entry.last() {
        entry = &entry[0..entry.len() - 1];
    }
    if entry.is_empty() {
        return Ok(None);
    }

    let (tls_secret_label, entry_payload) = match parse_tls12_secret(entry) {
        Some(xs) => (tls::TlsSecretLabel::Tls12, xs),
        None => match parse_tls13_secret(entry, CLIENT_HANDSHAKE_TRAFFIC_SECRET_LABEL) {
            Some(xs) => (tls::TlsSecretLabel::Tls13ClientHandshake, xs),
            None => match parse_tls13_secret(entry, SERVER_HANDSHAKE_TRAFFIC_SECRET_LABEL) {
                Some(xs) => (tls::TlsSecretLabel::Tls13ServerHandshake, xs),
                None => match parse_tls13_secret(entry, CLIENT_TRAFFIC_SECRET_0_LABEL) {
                    Some(xs) => (tls::TlsSecretLabel::Tls13ClientTraffic, xs),
                    None => match parse_tls13_secret(entry, SERVER_TRAFFIC_SECRET_0_LABEL) {
                        Some(xs) => (tls::TlsSecretLabel::Tls13ServerTraffic, xs),
                        None => return Err(()),
                    },
                },
            },
        },
    };

    let client_random_hex = &entry_payload[..CLIENT_RANDOM_LEN];
    let secret_hex = &entry_payload[(CLIENT_RANDOM_LEN + 1)..];

    let client_random = tls::ClientRandom(<_>::from_hex(client_random_hex).map_err(|_| ())?);

    let key = (tls_secret_label, client_random);
    let secret = match tls_secret_label {
        tls::TlsSecretLabel::Tls12 => {
            tls::TlsSecret::Tls12(decode_tls12_secret(secret_hex).ok_or(())?)
        }
        tls::TlsSecretLabel::Tls13ClientHandshake => tls::TlsSecret::Tls13ClientHandshake(
            tls::Tls13ClientHandshakeSecret(decode_tls13_secret(secret_hex).ok_or(())?),
        ),
        tls::TlsSecretLabel::Tls13ServerHandshake => tls::TlsSecret::Tls13ServerHandshake(
            tls::Tls13ServerHandshakeSecret(decode_tls13_secret(secret_hex).ok_or(())?),
        ),
        tls::TlsSecretLabel::Tls13ClientTraffic => tls::TlsSecret::Tls13ClientTraffic(
            tls::Tls13ClientTrafficSecret(decode_tls13_secret(secret_hex).ok_or(())?),
        ),
        tls::TlsSecretLabel::Tls13ServerTraffic => tls::TlsSecret::Tls13ServerTraffic(
            tls::Tls13ServerTrafficSecret(decode_tls13_secret(secret_hex).ok_or(())?),
        ),
    };

    Ok(Some(Entry {
        key,
        master_secret: secret,
    }))
}

impl Default for SSLKeyLogFile {
    fn default() -> Self {
        Self::new()
    }
}

impl SSLKeyLogFile {
    pub fn new() -> SSLKeyLogFile {
        SSLKeyLogFile {
            master_secrets: RwLock::new(HashMap::with_capacity(1024)),
        }
    }

    pub fn add_entries(&self, entry_lines: &[u8]) {
        for entry_part in entry_lines.split(|char| *char == b'\n') {
            match parse_sslkeylogfile_entry(entry_part) {
                Ok(None) => {}
                Ok(Some(entry)) => {
                    stallone::debug!("SSLKEYLOGFILE entry", entry: Entry = entry);
                    self.master_secrets
                        .write()
                        .entry(entry.key)
                        .or_insert_with(|| Arc::new(MasterSecretFuture::new()))
                        .populate(entry.master_secret);
                }
                Err(_) => {
                    stallone::warn!(
                        "Unable to parse SSLKEYLOGFILE entry",
                        entry_part: &[u8] = entry_part
                    );
                }
            }
        }
    }

    pub fn read_from_named_pipe<P: AsRef<Path>>(path: P) -> std::io::Result<Arc<Self>> {
        // TODO: rather than ignoring errors to mkfifo, do something in conjunction with stat.
        std::mem::drop(nix::unistd::mkfifo(
            path.as_ref(),
            nix::sys::stat::Mode::S_IRWXU,
        ));
        let out = Arc::new(Self::new());
        let me = out.clone();
        let path = path.as_ref().to_path_buf();
        std::thread::spawn(move || {
            stallone::info!("spawned thread to read SSLKEYLOGFILE");
            let mut buf = vec![0_u8; 4096];
            let mut f: Option<File> = None;
            loop {
                if f.is_none() {
                    for _ in 0..3 {
                        match File::open(path.as_path()) {
                            Ok(new_file) => {
                                stallone::debug!("successfully opened SSLKEYLOGFILE");
                                f = Some(new_file);
                                break;
                            }
                            Err(e) => {
                                stallone::warn!(
                                    "Unable to re-open SSLKEYLOGFILE",
                                    path: Path = path.as_path(),
                                    error: String = e.to_string(),
                                );
                            }
                        }
                        // TODO: sleep before retrying?
                    }
                }
                match f.as_mut().map(|f| f.read(&mut buf[..])) {
                    Some(Ok(0)) => {
                        stallone::debug!(
                            "about to re-open SSLKEYLOGFILE",
                            path: Path = path.as_path()
                        );
                        f = None;
                    }
                    Some(Ok(n)) => {
                        // NOTE: because this is a named pipe, each read should correspond to one entry
                        let entry_line = &buf[0..n];
                        me.add_entries(entry_line);
                    }
                    Some(Err(e)) => {
                        stallone::error!(
                            "Unable to read from SSLKEYLOGFILE",
                            msg: String = format!("{}", e)
                        );
                    }
                    None => {
                        stallone::error!("Failed to re-open SSLKEYLOGFILE");
                        return;
                    }
                }
            }
        });
        Ok(out)
    }

    pub fn blocking_get(&self, key: &SecretMapKey) -> tls::TlsSecret {
        {
            if let Some(secret) = self.get(key) {
                return secret;
            }
        }
        let future = {
            self.master_secrets
                .write()
                .entry(*key)
                .or_insert_with(|| Arc::new(MasterSecretFuture::new()))
                .clone()
        };
        let secret_type = &key.0;
        let client_random = &key.1;
        let start = std::time::Instant::now();
        stallone::info!(
            "Beginning wait for TLS secret",
            secret_type: &tls::TlsSecretLabel = secret_type,
            client_random: &tls::ClientRandom = client_random,
        );
        let out = future.join();
        let end = std::time::Instant::now();
        stallone::info!(
            "Waited for TLS secret",
            duration: std::time::Duration = end - start,
            secret_type: &tls::TlsSecretLabel = secret_type,
            client_random: &tls::ClientRandom = client_random,
        );
        out
    }

    pub fn get(&self, key: &SecretMapKey) -> Option<tls::TlsSecret> {
        self.master_secrets
            .read()
            .get(key)
            .and_then(|future| future.ask())
    }
}

impl TlsSecretProvider for SSLKeyLogFile {
    fn tls_secret(
        &self,
        label: tls::TlsSecretLabel,
        client_random: &tls::ClientRandom,
    ) -> tls::TlsSecret {
        self.blocking_get(&(label, *client_random))
    }
}

#[test]
fn test_multiple_lines() {
    const TEST_CASE: &[u8] = b"\
    CLIENT_RANDOM 8aa16672a0d08a81756c9db07f5a86166e917e104a7fd2bd8dc5de10b004821a \
    061457cbb21f1a76e97daa366a48fc466c2e2a558fa409beeed0b5e018131fa0213a65973d50748359650fad6a16b39a\
    \nCLIENT_RANDOM 599419c447761dd167af129398b321b5c5fc32e3ab3051999489f51bbb761b74 \
    ffc80a5db98507afeef0b659469a7700a50f772f2cda158cf78744cc85ee94b31445606c499a538a467e1915c1a37c68\
    \nCLIENT_RANDOM 94a5dd636a6fb1284e19a0072ea7f8c1b1a6f56cf91a542ec963552d52c37c4b \
    d15a9a5fa2c796c32f74bde27fc15ff8db25ac2d1d66b8fce32a838c0f62045ff72869aa8637798e6d5eeb3c67aaf094\
    \nCLIENT_RANDOM c6c4849b12799b275b2a3c24d66e5c1338d894b40eaa9917b1f5e47734176503 \
    18952bcbbdd30921e671c508f3b9d2f5c37c5416bf90992b4aacffff02eaa069a27f4515ed726757d73aeae2b80f6840\
    \nCLIENT_RANDOM 3c83137500236e92754f9b756788c075d86b45b5071018e2ecc34d952d326d6c \
    0e9ac4f43cb07b3dd4176647606fb7947702fe7258c1497468650ea587b2c7b26e72113f2c6978d5c9d3ef3a357e0644\
    \nCLIENT_RANDOM 37a0a1ee37ba43b3df8f8701641212aa3d9482156e23ca8ed6934f8437251cf2 \
    734a8cb1bb85f70a382d39a573e7873107878612281f34ccfac5834996dd6c0f3c1135f858e16a2e22424a5ab8990e96\
    \n";
    let ssl_key_log_file = SSLKeyLogFile::new();

    let ssl_key_log_file_lookup_tls12 = |key: tls::ClientRandom| match ssl_key_log_file
        .get(&(tls::TlsSecretLabel::Tls12, key))
        .unwrap()
    {
        tls::TlsSecret::Tls12(x) => x.0,
        x => panic!("Unexpected TLS secret type: {:?}", x),
    };

    ssl_key_log_file.add_entries(TEST_CASE);
    assert_eq!(
        &ssl_key_log_file_lookup_tls12(tls::ClientRandom([
            138, 161, 102, 114, 160, 208, 138, 129, 117, 108, 157, 176, 127, 90, 134, 22, 110, 145,
            126, 16, 74, 127, 210, 189, 141, 197, 222, 16, 176, 4, 130, 26
        ]))[..],
        &[
            6, 20, 87, 203, 178, 31, 26, 118, 233, 125, 170, 54, 106, 72, 252, 70, 108, 46, 42, 85,
            143, 164, 9, 190, 238, 208, 181, 224, 24, 19, 31, 160, 33, 58, 101, 151, 61, 80, 116,
            131, 89, 101, 15, 173, 106, 22, 179, 154
        ][..]
    );
    assert_eq!(
        &ssl_key_log_file_lookup_tls12(tls::ClientRandom([
            89, 148, 25, 196, 71, 118, 29, 209, 103, 175, 18, 147, 152, 179, 33, 181, 197, 252, 50,
            227, 171, 48, 81, 153, 148, 137, 245, 27, 187, 118, 27, 116
        ]))[..],
        &[
            255, 200, 10, 93, 185, 133, 7, 175, 238, 240, 182, 89, 70, 154, 119, 0, 165, 15, 119,
            47, 44, 218, 21, 140, 247, 135, 68, 204, 133, 238, 148, 179, 20, 69, 96, 108, 73, 154,
            83, 138, 70, 126, 25, 21, 193, 163, 124, 104
        ][..]
    );
    assert_eq!(
        &ssl_key_log_file_lookup_tls12(tls::ClientRandom([
            148, 165, 221, 99, 106, 111, 177, 40, 78, 25, 160, 7, 46, 167, 248, 193, 177, 166, 245,
            108, 249, 26, 84, 46, 201, 99, 85, 45, 82, 195, 124, 75
        ]))[..],
        &[
            209, 90, 154, 95, 162, 199, 150, 195, 47, 116, 189, 226, 127, 193, 95, 248, 219, 37,
            172, 45, 29, 102, 184, 252, 227, 42, 131, 140, 15, 98, 4, 95, 247, 40, 105, 170, 134,
            55, 121, 142, 109, 94, 235, 60, 103, 170, 240, 148
        ][..]
    );
    assert_eq!(
        &ssl_key_log_file_lookup_tls12(tls::ClientRandom([
            198, 196, 132, 155, 18, 121, 155, 39, 91, 42, 60, 36, 214, 110, 92, 19, 56, 216, 148,
            180, 14, 170, 153, 23, 177, 245, 228, 119, 52, 23, 101, 3
        ]))[..],
        &[
            24, 149, 43, 203, 189, 211, 9, 33, 230, 113, 197, 8, 243, 185, 210, 245, 195, 124, 84,
            22, 191, 144, 153, 43, 74, 172, 255, 255, 2, 234, 160, 105, 162, 127, 69, 21, 237, 114,
            103, 87, 215, 58, 234, 226, 184, 15, 104, 64
        ][..]
    );
    assert_eq!(
        &ssl_key_log_file_lookup_tls12(tls::ClientRandom([
            60, 131, 19, 117, 0, 35, 110, 146, 117, 79, 155, 117, 103, 136, 192, 117, 216, 107, 69,
            181, 7, 16, 24, 226, 236, 195, 77, 149, 45, 50, 109, 108
        ]))[..],
        &[
            14, 154, 196, 244, 60, 176, 123, 61, 212, 23, 102, 71, 96, 111, 183, 148, 119, 2, 254,
            114, 88, 193, 73, 116, 104, 101, 14, 165, 135, 178, 199, 178, 110, 114, 17, 63, 44,
            105, 120, 213, 201, 211, 239, 58, 53, 126, 6, 68
        ][..]
    );
    assert_eq!(
        &ssl_key_log_file_lookup_tls12(tls::ClientRandom([
            55, 160, 161, 238, 55, 186, 67, 179, 223, 143, 135, 1, 100, 18, 18, 170, 61, 148, 130,
            21, 110, 35, 202, 142, 214, 147, 79, 132, 55, 37, 28, 242
        ]))[..],
        &[
            115, 74, 140, 177, 187, 133, 247, 10, 56, 45, 57, 165, 115, 231, 135, 49, 7, 135, 134,
            18, 40, 31, 52, 204, 250, 197, 131, 73, 150, 221, 108, 15, 60, 17, 53, 248, 88, 225,
            106, 46, 34, 66, 74, 90, 184, 153, 14, 150
        ][..]
    );
}
