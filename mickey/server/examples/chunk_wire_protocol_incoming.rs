use bytes::Bytes;
use crossbeam::channel;
use mickey_server::chunk_wire_protocol::*;
use stallone;
use std::time::Instant;
use structopt::StructOpt;

#[derive(Debug, StructOpt)]
#[structopt(name = "chunk_wire_protocol_incoming", about = "Benchmark/Example")]
struct Opt {
    /// Package length
    #[structopt(default_value = "1048576")]
    package_length: usize,
}

fn main() {
    let opt = Opt::from_args();
    stallone::initialize(Default::default());
    let (chunks_s, chunks_r) = channel::unbounded();
    let (pkgs_s, _pkgs_r) = channel::unbounded();
    let outgoing_start = Instant::now();
    let mut chunk_writer = ChunkWriter::new(chunks_s);
    for _i in 1..100000 {
        let pkg = Bytes::from(vec![0; opt.package_length]);
        process_one_outgoing_pkg(pkg, &mut chunk_writer)
            .expect("Failed to process outgoing package.");
    }

    println!(
        "Outgoing packages processed in: {:?}",
        outgoing_start.elapsed()
    );

    chunk_writer.pad_remaining().expect("Failed to pad chunk.");
    chunk_writer.flush().expect("Failed to flush chunk.");

    let incoming_start = Instant::now();

    let mut chunk_reader = ChunkReader::new(chunks_r);
    for _i in 1..100000 {
        process_one_incoming_pkg(&pkgs_s, &mut chunk_reader)
            .expect("Failed to process incoming package.");
    }

    println!(
        "Incoming packages processed in: {:?}",
        incoming_start.elapsed()
    );
}
