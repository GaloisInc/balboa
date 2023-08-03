use std::{
    fs::File,
    path::{Path, PathBuf},
    sync::Arc,
};

use balboa_compression::{
    CanPreviewPlaintextData, CompressContext, Compressor, DecompressContext, Decompressor,
};
use memmap2::Mmap;
use parking_lot::RwLock;
use rustc_hash::FxHashMap;

use crate::{CompressContextWrapper, DecompressContextWrapper, PathResolver, ReplacerFactory};

struct MmapCompressorAndDecompressor<F>
where
    for<'a> F: FnMut(&'a [u8], &'a mut [u8]) + Send,
{
    apply_covert_data: F,
    pos: usize,
    src: Arc<Mmap>,
}

impl<F> Compressor for MmapCompressorAndDecompressor<F>
where
    for<'a> F: FnMut(&'a [u8], &'a mut [u8]) + Send,
{
    fn compress(&mut self, buf: &mut [u8]) {
        self.process_data(buf);
    }
}

impl<F> Decompressor for MmapCompressorAndDecompressor<F>
where
    for<'a> F: FnMut(&'a [u8], &'a mut [u8]) + Send,
{
    fn decompress(&mut self, buf: &mut [u8]) {
        self.process_data(buf);
    }
}

impl<F> MmapCompressorAndDecompressor<F>
where
    for<'a> F: FnMut(&'a [u8], &'a mut [u8]) + Send,
{
    fn process_data(&mut self, buf: &mut [u8]) {
        let end = self.pos.checked_add(buf.len());
        let data = end.and_then(|end| self.src.get(self.pos..end));
        if let Some(data) = data {
            (self.apply_covert_data)(data, buf);
        } else {
            stallone::warn!(
                "static mmap HTTP rewrite data out of range",
                start: usize = self.pos,
                end: Option<usize> = end,
                len: usize = self.src.len()
            );
        }
        self.pos = self.pos.saturating_add(buf.len());
    }
}
impl<F> CanPreviewPlaintextData for MmapCompressorAndDecompressor<F>
where
    for<'a> F: FnMut(&'a [u8], &'a mut [u8]) + Send,
{
    fn preview(&mut self, buf: &[u8]) {
        self.pos = self.pos.saturating_add(buf.len());
    }
}

struct MmapPathReplacer(Arc<Mmap>);
impl ReplacerFactory for MmapPathReplacer {
    fn new_compressor(&self, mut ctx: CompressContextWrapper) -> Box<dyn Compressor + Send> {
        Box::new(MmapCompressorAndDecompressor {
            apply_covert_data: move |file, buf| {
                debug_assert_eq!(file, buf);
                ctx.recv_covert_bytes(buf);
            },
            pos: 0,
            src: self.0.clone(),
        })
    }

    fn new_decompressor(&self, mut ctx: DecompressContextWrapper) -> Box<dyn Decompressor + Send> {
        Box::new(MmapCompressorAndDecompressor {
            apply_covert_data: move |file, buf| {
                ctx.send_covert_bytes(buf);
                buf.copy_from_slice(file);
            },
            pos: 0,
            src: self.0.clone(),
        })
    }

    fn known_size(&self) -> Option<usize> {
        Some(self.0.len())
    }
}

/// Resolve HTTP paths to file paths.
pub struct StaticFileDirectory {
    root: PathBuf,
    // TODO: use an LRU cache
    cache: RwLock<FxHashMap<PathBuf, Arc<Mmap>>>,
}
impl StaticFileDirectory {
    pub fn new(root: &Path) -> std::io::Result<Self> {
        let root = std::fs::canonicalize(root)?;
        if !std::fs::metadata(&root)?.is_dir() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "Expected directory",
            ));
        }
        Ok(StaticFileDirectory {
            root,
            cache: Default::default(),
        })
    }
}
impl PathResolver for StaticFileDirectory {
    fn resolve_uri(
        &self,
        mut path: &[u8],
    ) -> Option<Arc<dyn ReplacerFactory + Send + Sync + 'static>> {
        // Strip out query.
        if let Some(idx) = memchr::memchr(b'?', path) {
            path = &path[0..idx];
        }
        #[cfg(target_os = "windows")]
        {
            todo!("Path traversal attack is still possible since windows can use \\ or /");
        }
        let path = if let Ok(path) = std::str::from_utf8(path) {
            path
        } else {
            stallone::warn!("Path wasn't utf-8");
            return None;
        };
        // TODO: is this secure against path traversal attacks?
        let mut fs_path = PathBuf::with_capacity(path.len());
        for part in path.split('/') {
            match part {
                "" | "." => {}
                ".." => {
                    if !fs_path.pop() {
                        stallone::warn!("'..' path component on empty path");
                        return None;
                    }
                }
                _ => {
                    fs_path.push(part);
                }
            }
        }
        if let Some(out) = self.cache.read().get(&fs_path) {
            return Some(Arc::new(MmapPathReplacer(out.clone())));
        }
        fs_path = self.root.join(fs_path);
        let f = if let Ok(f) = File::open(&fs_path) {
            f
        } else {
            stallone::warn!("unable to open file", path: PathBuf = fs_path,);
            return None;
        };
        if let Ok(map) = unsafe {
            // SAFETY: we assume that these files won't be modified while they're in-use.
            Mmap::map(&f)
        } {
            let map = Arc::new(map);
            self.cache.write().insert(fs_path.clone(), map.clone());
            Some(Arc::new(MmapPathReplacer(map)))
        } else {
            stallone::warn!("Failed to mmap file", path: PathBuf = fs_path,);
            None
        }
    }
}
