use parking_lot::Mutex;
use std::{sync::Arc, thread};

#[derive(Clone)]
pub struct ThreadSpawner {
    // We don't use thread names, since they're limited to 16 chars on Linux.
    threads: Arc<Mutex<Vec<(String, thread::JoinHandle<()>)>>>,
}
impl ThreadSpawner {
    pub fn new() -> Self {
        ThreadSpawner {
            threads: Arc::new(Default::default()),
        }
    }

    pub fn internal_spawn_thread(&self, name: String, body: impl FnOnce() -> () + Send + 'static) {
        let handle = thread::spawn(body);
        self.threads.lock().push((name, handle));
    }

    pub fn wait_for_all(&self) {
        loop {
            let handle = self.threads.lock().pop();
            match handle {
                None => {
                    break;
                }
                Some((name, handle)) => {
                    log::info!("Waiting for thread {} to end", name);
                    let _ = handle.join();
                }
            }
        }
    }
}

#[macro_export]
macro_rules! spawn_thread {
    (
        $spawner:expr,
        thread $thread_name:ident {
            $(
                $id:ident : $ty:ty = $value:expr
            ),*
            $(,)?
        },
        $body:expr
    ) => {{
        use stallone::LoggableMetadata;
        #[derive(Debug, LoggableMetadata)]
        struct $thread_name {
            $($id : $ty),*
        }
        let name = $thread_name {
            $($id : $value.clone()),*
        };
        let name_str = format!("{:?}", name);
        let body = $body;
        $spawner.internal_spawn_thread(name_str, move || {
            stallone::info!(
                "Started thread",
                #[context(true)]
                thread_name: $thread_name = name,
            );
            std::mem::drop(name);
            body();
        });
    }};
}
