use std::io;

pub fn spawn(name: &str, body: impl FnOnce() + Send + 'static) {
    if let Err(e) = try_spawn(name, body) {
        panic!("could not start the {name} thread: {e}");
    }
}

pub fn try_spawn(name: &str, body: impl FnOnce() + Send + 'static) -> io::Result<()> {
    std::thread::Builder::new().name(name.to_string()).spawn(body).map(drop)
}
