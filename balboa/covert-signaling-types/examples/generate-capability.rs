use balboa_covert_signaling_types::*;
use std::{net::Ipv4Addr, path::PathBuf};
use structopt::StructOpt;

#[derive(StructOpt, Debug)]
struct Opt {
    #[structopt(long)]
    /// 16-byte hex-encoded server secret key.
    server_secret: String,

    #[structopt(long)]
    /// 32-byte hex-encoded ROCKY pre-shared secret.
    rocky_secret: String,

    #[structopt(long)]
    /// Path to a DER-encoded TLS public signature key.
    pinned_server_pub_key: PathBuf,

    #[structopt(long)]
    /// IPv4 address of target of capability.
    address: Ipv4Addr,

    #[structopt(long)]
    /// 64-bit unsigned integer within the identity-space of
    /// capability generator.
    covert_signaling_identity: u64,
}

fn main() {
    let opt = Opt::from_args();

    let server_covert_signaling_secret = ServerCovertSignalingSecret::from_bytes(
        hex::decode(&opt.server_secret)
            .expect("Unable to decode secret key")
            .try_into()
            .expect("Unable to decode secret key"),
    );
    let covert_identity = opt.covert_signaling_identity;
    let covert_signaling_token = server_covert_signaling_secret.generate_token(covert_identity);

    let rocky_secret = RockySecret(
        hex::decode(&opt.rocky_secret)
            .expect("Unable to decode shared key")
            .try_into()
            .expect("Unable to decode shared key"),
    );

    let pinned_server_key = PinnedServerPubKey::from_der(
        std::fs::read(opt.pinned_server_pub_key).expect("Unable to read pinned key"),
    );
    let capability = Capability {
        covert_signaling_token,
        rocky_secret,
        pinned_server_pub_key: pinned_server_key,
        address: Address { ip: opt.address },
    };

    println!("{}", &serde_json::to_string(&capability).unwrap())
}
