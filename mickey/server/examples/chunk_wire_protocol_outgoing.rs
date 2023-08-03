use bytes::Bytes;
use crossbeam::channel;
use mickey_server::chunk_wire_protocol::*;
use stallone;
use structopt::StructOpt;

#[derive(Debug, StructOpt)]
#[structopt(name = "chunk_wire_protocol_incoming", about = "Benchmark/Example")]
struct Opt {
    /// Package length
    #[structopt(default_value = "1024")]
    package_length: usize,
}

fn main() {
    let opt = Opt::from_args();
    stallone::initialize(Default::default());
    let (chunks_s, _chunks_r) = channel::unbounded();
    let mut chunk_writer = ChunkWriter::new(chunks_s);
    for _i in 1..10000000 {
        let pkg = Bytes::from(vec![0; opt.package_length]);
        process_one_outgoing_pkg(pkg, &mut chunk_writer)
            .expect("Failed to process outpoing package.");
    }
}
