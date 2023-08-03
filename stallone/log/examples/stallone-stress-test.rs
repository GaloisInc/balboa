use stallone::StalloneConfig;

#[inline(never)]
fn body() {
    stallone::info!("salut");
}

fn main() {
    const N: u32 = 100_000_000;
    let buffer_size = (N as usize) * 32;
    dbg!(buffer_size);
    stallone::initialize(StalloneConfig {
        buffer_size,
        log_level_capacities: [u64::MAX; stallone::NUM_LEVELS],
        ..Default::default()
    });
    let start = std::time::Instant::now();
    stallone::info!("First message");
    println!("First message duration {:?}", start.elapsed());
    println!("NOTE: these numbers won't be accurate if any log events get dropped.");
    let start = std::time::Instant::now();
    for _ in 0..N {
        body();
    }
    let total = start.elapsed();
    println!(
        "[No args] Stress test DURATION {:?} (per log event {:?})",
        total,
        total / N
    );
}
