use crate::{
    CoroutineBasedStreamRewriter, PreviewingCoroutineBasedStreamRewriter, SkipThroughNeedle,
};
use proptest::prelude::*;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};

proptest! {
    #[test]
    fn nested_rewrites(buffers in any::<Vec<Vec<u8>>>()) {
        fn f1(x: u8) -> u8 {
            x.wrapping_add(11)
        }
        fn f2(x: u8) -> u8 {
            x.wrapping_mul(3)
        }
        let mut inner = CoroutineBasedStreamRewriter::<()>::new(|mut gs| async move {
            loop {
                gs.advance_exact_with_modification(1000, |buf| {
                    for byte in buf.iter_mut() {
                        *byte = f2(*byte);
                    }
                })
                .await;
            }
        });
        let mut outer = CoroutineBasedStreamRewriter::<()>::new(|mut gs| async move {
            loop {
                gs.advance_exact_with_modification(1000, |buf| {
                    for byte in buf.iter_mut() {
                        *byte = f1(*byte);
                    }
                    inner.rewrite(buf);
                })
                .await;
            }
        });
        for mut actual in buffers.into_iter() {
            let expected: Vec<u8> = actual.iter().cloned().map(|byte| f2(f1(byte))).collect();
            outer.rewrite(&mut actual[..]);
            prop_assert_eq!(expected, actual);
        }
    }
}

type Returny = Option<u8>;

proptest! {
    #[test]
    fn yielding_rewrites(buffers in any::<Vec<Vec<u8>>>()) {
        let mut rewriter = CoroutineBasedStreamRewriter::<Returny>::new(|mut gs| async move {
            loop {
                let chunk = gs.current_chunk().await;
                let first_byte = chunk.first().copied();
                if let Some(x) = first_byte {
                    gs.yield_value(Some(x));
                }
                gs.advance_without_modifying(1).await;
            }
        });
        for mut actual in buffers.into_iter() {
            let r = rewriter.rewrite(&mut actual);
            prop_assert_eq!(r, actual.last().copied());
        }
    }
}

fn run_test_skip_through_needle(chunks: Vec<Vec<u8>>, needle: Vec<u8>) {
    let joined: Vec<u8> = chunks.iter().flat_map(|v| v.iter().copied()).collect();
    let joined_idx = memchr::memmem::find(joined.as_slice(), needle.as_slice()).unwrap();
    let finished = Arc::new(AtomicBool::new(false));
    let mut coro = PreviewingCoroutineBasedStreamRewriter::new({
        let finished = finished.clone();
        move |mut gs| async move {
            let mut skipper = SkipThroughNeedle::new(needle.as_slice());
            skipper.skip_through_needle(&mut gs).await;
            // We don't want to flip the buffer if this is empty.
            let mut chunk = &gs.whole_immutable_buffer()[gs.position..];
            let expected = &joined[joined_idx + needle.len()..];
            if !expected.is_empty() && chunk.is_empty() {
                chunk = gs.current_buffer().await; // Try flipping the buffer!
            }
            assert_eq!(chunk, expected);
            finished.store(true, Ordering::Relaxed);
            let chunk_len = chunk.len();
            if chunk_len != 0 {
                gs.advance_without_modifying(chunk_len).await;
            }
            gs.current_buffer().await; // Force the buffer flip.
            panic!("This should be in the last chunk!");
        }
    });
    for chunk in chunks.into_iter() {
        coro.preview(chunk.as_slice());
    }
    assert!(finished.load(Ordering::Relaxed));
}

#[test]
fn test_skip_through_needle_manual() {
    run_test_skip_through_needle(vec![b"abc".to_vec(), b"a.xd".to_vec()], b".".to_vec());
    run_test_skip_through_needle(vec![b"abc".to_vec(), b"a.".to_vec()], b".".to_vec());
    run_test_skip_through_needle(vec![b"abc".to_vec(), b".xd".to_vec()], b".".to_vec());
    run_test_skip_through_needle(vec![b"abc".to_vec(), b"!@xd".to_vec()], b"!@".to_vec());
    run_test_skip_through_needle(vec![b"abc".to_vec(), b"!@".to_vec()], b"!@".to_vec());
    run_test_skip_through_needle(vec![b"abc".to_vec(), b"x!@".to_vec()], b"!@".to_vec());
    run_test_skip_through_needle(vec![b"abc".to_vec(), b"x!@t".to_vec()], b"!@".to_vec());
    run_test_skip_through_needle(vec![b"abc!".to_vec(), b"@t".to_vec()], b"!@".to_vec());
    run_test_skip_through_needle(
        vec![
            b"abc!".to_vec(),
            b"@".to_vec(),
            b"#$%".to_vec(),
            b"t".to_vec(),
        ],
        b"!@#$%".to_vec(),
    );
    run_test_skip_through_needle(
        vec![
            b"abc!".to_vec(),
            b"@".to_vec(),
            b"#$".to_vec(),
            b"%t".to_vec(),
        ],
        b"!@#$%".to_vec(),
    );
    run_test_skip_through_needle(
        vec![b"abc!".to_vec(), b"!@#$%".to_vec(), b"t".to_vec()],
        b"!@#$%".to_vec(),
    );
}
