use balboa_coroutine::GenState;

pub(crate) const OGG_VERSION_DENOTING_ROCKY_MANGLING: u8 = 42;

pub(crate) async fn read_payload_len(gs: &mut GenState) -> usize {
    let num_page_segments = {
        let mut buf = [0];
        gs.read_exact(&mut buf).await;
        buf[0]
    } as usize;
    let mut payload_len = 0;
    for _ in 0..num_page_segments {
        let mut buf = [0];
        gs.read_exact(&mut buf).await;
        payload_len += usize::from(buf[0]);
    }
    payload_len
}

/// Returns the number of bytes skipped while looking.
pub(crate) async fn scan_for_four_byte_string(gs: &mut GenState, target: &[u8]) -> usize {
    let mut skipped_bytes = 0;
    assert_eq!(target.len(), 4);
    let mut buf = [0; 4];
    gs.read_exact(&mut buf).await;
    while &buf[..] != target {
        // Drop the first character.
        buf[0] = buf[1];
        buf[1] = buf[2];
        buf[2] = buf[3];
        skipped_bytes += 1;
        gs.read_exact(&mut buf[3..4]).await;
    }
    skipped_bytes
}
