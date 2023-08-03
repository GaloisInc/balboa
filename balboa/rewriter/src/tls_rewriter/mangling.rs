use super::{
    utils::{DefaultInputMacVerifier, PassthruOutputTagMangler},
    Result,
};
use crate::{
    tls,
    tls_rewriter::{
        rocky_crypto::CryptoParameters,
        shared_state::TLSConnectionSharedState,
        tls_record_parser,
        utils::{
            mangle_application_data, NormalTLSTaggerAndKeyStreamFactory,
            RockyTaggerAndKeyStreamFactory,
        },
        IncomingOrOutgoing, TLSRewriterMode,
    },
    StreamChangeData,
};
use balboa_compression::{Compressor, DecompressContext, Decompressor};
use parking_lot::Mutex;
use std::sync::Arc;

pub(crate) struct BufferingIncomingDecompressContext(Arc<Mutex<Vec<u8>>>);
impl BufferingIncomingDecompressContext {
    pub(crate) fn new() -> (
        Box<dyn DecompressContext + Sync + Send + 'static>,
        Arc<Mutex<Vec<u8>>>,
    ) {
        let buf = Arc::new(Mutex::new(Vec::new()));
        let buf2 = buf.clone();
        (Box::new(BufferingIncomingDecompressContext(buf)), buf2)
    }
}
impl DecompressContext for BufferingIncomingDecompressContext {
    fn send_covert_bytes(&mut self, src: &[u8]) {
        self.0.lock().extend_from_slice(src);
    }
}

pub(crate) async fn incoming<'a>(
    mode: TLSRewriterMode,
    decompress_buffer: Arc<Mutex<Vec<u8>>>,
    decompress_context: &mut (dyn DecompressContext + Send + 'static),
    decompressor: &mut (dyn Decompressor + Send + 'static),
    _ss: &TLSConnectionSharedState,
    cp: CryptoParameters,
    mut hdr: tls::RecordHeader,
    mut body: tls_record_parser::ParseRecordBody<'a, StreamChangeData>,
) -> Result<()> {
    let mode = !mode;
    loop {
        let rp = if hdr.record_type == tls::RecordType::ApplicationData {
            {
                let mut db = decompress_buffer.lock();
                stallone::warn_assert!(db.is_empty());
                db.clear();
            }
            let (rp, ()) = mangle_application_data(
                hdr,
                &cp.cipher_suite,
                body,
                &RockyTaggerAndKeyStreamFactory(cp.rocky_key(mode)),
                DefaultInputMacVerifier,
                &NormalTLSTaggerAndKeyStreamFactory(cp.tls_key(mode)),
                PassthruOutputTagMangler,
                |buf| {
                    decompressor.decompress(buf);
                },
                IncomingOrOutgoing::Incoming,
                true,
            )
            .await?;
            // If we've authenticated successfully, then flush!
            {
                let mut db = decompress_buffer.lock();
                if !db.is_empty() {
                    decompress_context.send_covert_bytes(&db[..]);
                    db.clear();
                }
            }
            rp
        } else {
            body.passively_discard_rest_of_body().await
        };
        let (hdr2, body2) = rp.parse_header().await?;
        hdr = hdr2;
        body = body2;
    }
}

pub(crate) async fn outgoing<'a>(
    mode: TLSRewriterMode,
    compressor: &mut (dyn Compressor + Send + 'static),
    _ss: &TLSConnectionSharedState,
    cp: CryptoParameters,
    mut hdr: tls::RecordHeader,
    mut body: tls_record_parser::ParseRecordBody<'a, ()>,
) -> Result<()> {
    loop {
        let rp = if hdr.record_type == tls::RecordType::ApplicationData {
            let (rp, ()) = mangle_application_data(
                hdr,
                &cp.cipher_suite,
                body,
                &NormalTLSTaggerAndKeyStreamFactory(cp.tls_key(mode)),
                DefaultInputMacVerifier,
                &RockyTaggerAndKeyStreamFactory(cp.rocky_key(mode)),
                PassthruOutputTagMangler,
                |buf| {
                    compressor.compress(buf);
                },
                IncomingOrOutgoing::Outgoing,
                true,
            )
            .await?;
            rp
        } else {
            body.passively_discard_rest_of_body().await
        };
        let (hdr2, body2) = rp.parse_header().await?;
        hdr = hdr2;
        body = body2;
    }
}
