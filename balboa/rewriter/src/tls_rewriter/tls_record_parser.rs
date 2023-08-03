use crate::{
    tls::{self, SequenceNumber},
    tls_rewriter::{errors::TLSRewriterError, GenState, Result},
};

pub(crate) enum SeqnumState {
    HandshakeInProgress,
    HandshakeComplete,
    SequenceNumber(tls::SequenceNumber),
    SawChangeCipherSpec(tls::SequenceNumber),
}

impl SeqnumState {
    fn get(&self) -> Option<tls::SequenceNumber> {
        match self {
            SeqnumState::SequenceNumber(x) => Some(*x),
            _ => None,
        }
    }

    fn increment(&mut self) {
        match self {
            SeqnumState::HandshakeInProgress => {}
            SeqnumState::HandshakeComplete => {
                stallone::debug!("Saw first record after cipher change spec.");
                self.new_sequence();
            }
            SeqnumState::SequenceNumber(sn) => sn.increment(),
            SeqnumState::SawChangeCipherSpec(sn) => *self = SeqnumState::SequenceNumber(*sn),
        }
    }

    fn new_sequence(&mut self) {
        *self = SeqnumState::SequenceNumber(SequenceNumber(0));
    }

    /// In TLS 1.2, seeing the ChangeCipherSpec record guarantees that the subsequent records will
    /// be encrypted with application data. That message will only appear after the handshake, so
    /// this method will be called while `self` is in the `HandshakeInProgress` state.
    ///
    /// In TLS 1.3, the ChangeCipherSpec message is optional, so `self` will be initialized to the
    /// `SequenceNumber` state by the time this method is called. Furthermore, in TLS 1.3, the
    /// passage of a ChangeCipherSpec message doesn't count towards incrementing the sequence
    /// number. Thus, we need to maintain the sequence number at a constant value for this record.
    fn saw_change_cipher_spec(&mut self) {
        match self {
            SeqnumState::HandshakeInProgress => {
                stallone::debug!("Saw ChangeCipherSpec. Initializing Seqnum");
                *self = SeqnumState::HandshakeComplete;
            }
            SeqnumState::SequenceNumber(sn) => *self = SeqnumState::SawChangeCipherSpec(*sn),
            _ => {}
        }
    }
}

pub(crate) struct CommonState {
    pub(crate) seqnum: SeqnumState,
}

impl CommonState {
    pub(crate) fn new() -> Self {
        Self {
            seqnum: SeqnumState::HandshakeInProgress,
        }
    }
}

pub(crate) struct AboutToParseHeader<'a, R: Default> {
    common: CommonState,
    gen: &'a mut GenState<R>,
}

impl<'a, R: Default> AboutToParseHeader<'a, R> {
    pub(crate) fn new(gen: &'a mut GenState<R>) -> Self {
        AboutToParseHeader {
            common: CommonState::new(),
            gen,
        }
    }

    pub(crate) fn start_new_sequence(&mut self) {
        self.common.seqnum.new_sequence();
    }

    pub(crate) async fn parse_header(self) -> Result<(tls::RecordHeader, ParseRecordBody<'a, R>)> {
        let (hdr, next_state) = self.parse_header_without_checking_version().await?;
        if hdr.version != tls::TLS_VERSION_1_2 {
            return Err(TLSRewriterError::TLSVersionMismatch {
                actual: hdr.version,
                expected: tls::TLS_VERSION_1_2,
            });
        }
        Ok((hdr, next_state))
    }

    pub(crate) async fn parse_header_without_checking_version(
        mut self,
    ) -> Result<(tls::RecordHeader, ParseRecordBody<'a, R>)> {
        let mut buf = [0; 5];
        self.gen.read_exact(&mut buf).await;
        let record_type = tls::RecordType::from(buf[0]);
        let version = u16::from_be_bytes([buf[1], buf[2]]);
        let size = u16::from_be_bytes([buf[3], buf[4]]) as usize;
        if size >= tls::RECORD_MAX_SIZE {
            return Err(TLSRewriterError::RecordTooBig { size });
        }
        let header = tls::RecordHeader {
            record_type,
            version,
            size,
        };
        if header.record_type == tls::RecordType::ChangeCipherSpec {
            self.common.seqnum.saw_change_cipher_spec();
        }
        stallone::debug!(
            "Parsed TLS record header",
            header: tls::RecordHeader = header
        );
        let mut body = ParseRecordBody {
            gen: self.gen,
            size,
            common: self.common,
        };
        if header.record_type == tls::RecordType::Alert {
            if body.sequence_number().is_some() {
                return Err(TLSRewriterError::SawEncryptedAlert);
            }
            if header.size != 2 {
                return Err(TLSRewriterError::SawInvalidLengthAlert {
                    length: header.size,
                });
            }
            let mut alert_bytes = [0_u8; 2];
            body.passively_read_part_of_body(&mut alert_bytes).await;
            return Err(construct_alert_error(&alert_bytes));
        }
        Ok((header, body))
    }
}

pub(crate) struct ParseRecordBody<'a, R: Default> {
    pub(crate) gen: &'a mut GenState<R>,
    pub(crate) common: CommonState,
    pub(crate) size: usize,
}

impl<'a, R: Default> ParseRecordBody<'a, R> {
    pub(crate) fn start_new_sequence(&mut self) {
        self.common.seqnum.new_sequence();
    }

    pub(crate) async fn passively_read_part_of_body(&mut self, dst: &mut [u8]) -> usize {
        let out = self.size.min(dst.len());
        self.gen.read_exact(&mut dst[0..out]).await;
        self.size -= out;
        out
    }

    /// Reads the remainder of the TLS record into `dst`.
    ///
    /// Panics if `dst` isn't the same size as the remaining size of the TLS record. `dst` should
    /// be sized based on the `size` field of the associated `tls::RecordHeader`.
    pub(crate) async fn passively_read_rest_of_body(
        mut self,
        dst: &mut [u8],
    ) -> AboutToParseHeader<'a, R> {
        assert_eq!(self.size, dst.len());
        self.gen.read_exact(dst).await;
        self.common.seqnum.increment();
        AboutToParseHeader {
            common: self.common,
            gen: self.gen,
        }
    }

    pub(crate) fn sequence_number(&self) -> Option<tls::SequenceNumber> {
        self.common.seqnum.get()
    }

    pub(crate) async fn passively_discard_rest_of_body(mut self) -> AboutToParseHeader<'a, R> {
        self.gen.advance_without_modifying(self.size).await;
        self.common.seqnum.increment();
        AboutToParseHeader {
            common: self.common,
            gen: self.gen,
        }
    }

    /// Identical to `advance_exact_with_modification`, but use a `thunk` which contains a mutable
    /// reference to the value yielded by the `gen` coroutine.
    pub(crate) async fn advance_exact_with_modification_yielding(
        &mut self,
        n: usize,
        thunk: impl FnMut(&mut [u8], &mut R, usize),
    ) -> usize {
        let n = n.min(self.size);
        self.size -= n;
        self.gen
            .advance_exact_with_modification_yielding(n, thunk)
            .await;
        n
    }

    pub(crate) async fn advance_exact_with_modification(
        &mut self,
        n: usize,
        thunk: impl FnMut(&mut [u8]),
    ) -> usize {
        let n = n.min(self.size);
        self.size -= n;
        self.gen.advance_exact_with_modification(n, thunk).await;
        n
    }
}

fn construct_alert_error(bytes: &[u8]) -> TLSRewriterError {
    let alert_u16 = u16::from_be_bytes([bytes[0], bytes[1]]);
    let alert = tls::Alert::from(alert_u16);
    TLSRewriterError::SawUnencryptedAlert { alert }
}
