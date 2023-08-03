use std::{
    fs::File,
    io::{Read, Seek, SeekFrom},
    path::Path,
};

pub fn read_ogg_bodies<P: AsRef<Path>>(p: P) -> std::io::Result<Vec<u8>> {
    let mut file = File::open(p)?;
    let file_size = file.seek(SeekFrom::End(0))?;
    let mut out = Vec::with_capacity(usize::try_from(file_size).unwrap_or(0));
    file.seek(SeekFrom::Start(0))?;
    let mut file = std::io::BufReader::with_capacity(1024 * 1024, file);
    loop {
        let mut header = [0; 27];
        if let Err(e) = file.read_exact(&mut header[..]) {
            if e.kind() == std::io::ErrorKind::UnexpectedEof {
                return Ok(out);
            } else {
                return Err(e);
            }
        }
        // TODO: better error handling
        assert_eq!(&header[0..4], b"OggS");
        let num_segments = header[26] as usize;
        let mut payload_size = 0;
        for _ in 0..num_segments {
            let mut buf = [0; 1];
            file.read_exact(&mut buf[..])?;
            payload_size += buf[0] as usize;
        }
        out.extend(std::iter::repeat(0).take(payload_size));
        let n = out.len() - payload_size;
        file.read_exact(&mut out[n..])?;
    }
}
