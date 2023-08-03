use stallone::LoggableMetadata;
use std::net;

#[derive(LoggableMetadata, Debug)]
struct Blarg<T> {
    another: &'static str,
    x: u32,
    t: T,
}

#[derive(LoggableMetadata, Debug)]
enum SampleEnum<T> {
    AUnit,
    BUnit,
    ATupleLike(u32, u64),
    StructLike { t: T, y: u8 },
}

#[derive(LoggableMetadata, Debug)]
struct Sentinel;

#[derive(LoggableMetadata, Debug)]
struct Pair(u32, u32);

#[inline(never)]
// This function is referred to, by name, in test_stallone.py
fn log_simple_test_string() {
    stallone::info!("this is a simple test string");
}

fn main() {
    stallone::info!("Here's a string that's logged before initialization. It should be dropped.");
    stallone::initialize(Default::default());
    log_simple_test_string();
    stallone::info!(
        "test numbers",
        one_twenty_eight_signed: i128 = -1329227995784915872903807060280344576,
        one_twenty_eight_unsigned: u128 = 340282366920938463463374607431768211414,
    );
    stallone::info!(
        "Test result",
        ok: Result<&'static str, i32> = Ok("this is okay"),
        err: Result<&'static str, i32> = Err(666),
    );
    stallone::info!(
        "derive test enum",
        a_unit: SampleEnum<u8> = SampleEnum::AUnit,
        b_unit: SampleEnum<u8> = SampleEnum::BUnit,
        a_tuple_like: SampleEnum<u8> = SampleEnum::ATupleLike(4, 6),
        struct_like: SampleEnum<u8> = SampleEnum::StructLike { t: 1, y: 89 },
    );
    stallone::info!(
        "derive test blarg",
        blarg: Blarg<u8> = Blarg {
            x: 12,
            t: 42,
            another: "Hello"
        },
        pair: Pair = Pair(34, 35),
        sentinel: Sentinel = Sentinel,
    );
    stallone::info!(
        "Tuple test",
        unit: () = (),
        #[context(true)]
        unary: (i32,) = (1,),
        binary: (u32, i128) = (1, 2),
    );
    stallone::info!(
        "System time test",
        current_time: std::time::SystemTime = std::time::SystemTime::now(),
    );
    stallone::info!(
        "Collections",
        names: std::collections::HashSet<String> = vec!["Joe".to_string(), "Bob".to_string()]
            .into_iter()
            .collect(),
        phonebook: std::collections::BTreeMap<String, u32> =
            vec![("Joe".to_string(), 123), ("Bob".to_string(), 456)]
                .into_iter()
                .collect(),
    );
    stallone::info!(
        "IP address tests",
        ipv4: net::Ipv4Addr = net::Ipv4Addr::LOCALHOST,
        ipv6: net::Ipv6Addr = net::Ipv6Addr::LOCALHOST,
        ip_ipv4: net::IpAddr = net::IpAddr::V4(net::Ipv4Addr::LOCALHOST),
        ip_ipv6: net::IpAddr = net::IpAddr::V6(net::Ipv6Addr::LOCALHOST),
        socket_ipv4: net::SocketAddrV4 = net::SocketAddrV4::new(net::Ipv4Addr::LOCALHOST, 0xF0F0),
        socket_ipv6: net::SocketAddrV6 =
            net::SocketAddrV6::new(net::Ipv6Addr::LOCALHOST, 0xF0F0, 11, 12),
        socket_ip_ipv4: net::SocketAddr =
            net::SocketAddr::V4(net::SocketAddrV4::new(net::Ipv4Addr::LOCALHOST, 0xF0F0)),
        socket_ip_ipv6: net::SocketAddr = net::SocketAddr::V6(net::SocketAddrV6::new(
            net::Ipv6Addr::LOCALHOST,
            0xF0F0,
            11,
            12
        )),
    );
}
