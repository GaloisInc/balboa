use balboa_covert_signaling_types::PinnedServerPubKey;
use parking_lot::RwLock;
use stallone_common::{positioned_io_result, PositionedIOResult};
use std::{collections::HashMap, io::Read, net::IpAddr, path::PathBuf, sync::Arc};

/// This struct manages the secrets needed for Rocky + Mickey. This includes the pinned public keys
/// and the rocky keys.
pub struct RockyCryptoSecrets {
    base_path: PathBuf,
    rocky_keys: RwLock<HashMap<IpAddr, [u8; 32]>>,
    tls_keys: RwLock<HashMap<IpAddr, Arc<PinnedServerPubKey>>>,
}

impl RockyCryptoSecrets {
    /// Construct a new `RockyCryptoSecrets` struct populated with the contents of the `base_path`
    /// directory. This folder sohuld contain:
    /// * `<IP address>.rocky-key`: files like these contain the 32-byte binary-encoded rocky secret when talking to the given IP
    /// * `<IP address>.der`: these files contain the DER-encoded public keys which will be used when communicating with the given IP
    pub fn new(base_path: PathBuf) -> Self {
        RockyCryptoSecrets {
            base_path,
            rocky_keys: Default::default(),
            tls_keys: Default::default(),
        }
    }

    pub fn rocky_key(&self, other: IpAddr) -> PositionedIOResult<[u8; 32]> {
        if let Some(out) = self.rocky_keys.read().get(&other) {
            return Ok(out.clone());
        }
        let path = self.base_path.join(format!("{}.rocky-key", other));
        let mut f = positioned_io_result!(std::fs::File::open(path))?;
        let mut key = [0; 32];
        positioned_io_result!(f.read_exact(&mut key[..]))?;
        self.rocky_keys.write().insert(other, key);
        Ok(key)
    }

    pub fn tls_key(&self, ip: IpAddr) -> PositionedIOResult<Arc<PinnedServerPubKey>> {
        if let Some(key) = self.tls_keys.write().get(&ip) {
            return Ok(key.clone());
        }
        let path = self.base_path.join(format!("{}.der", ip));
        let key = Arc::new(PinnedServerPubKey::from_der(positioned_io_result!(
            std::fs::read(path)
        )?));
        self.tls_keys.write().insert(ip, key.clone());
        Ok(key)
    }
}
