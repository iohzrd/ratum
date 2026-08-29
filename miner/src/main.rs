use ratum::header::blake2b_256;
use ratum::target;
use std::io::{BufRead, BufReader, Write};
use std::net::TcpStream;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex};

const HEADER_LEN: usize = 80;
const EXTRANONCE_LEN: usize = 16;

#[derive(Clone)]
struct Job {
    job_id: String,
    /// The notify's prevhash parameter: for a version 2 job this is the gateway's
    /// prevblock_hidden, not the previous block hash.
    prevhash: [u8; 32],
    coinb1: Vec<u8>,
    coinb2: Vec<u8>,
    ntime: [u8; 8],
    ntime_hex: String,
}

/// What the reader thread has received from the gateway. `generation` counts the jobs it has
/// recorded; the mining threads compare it against the one they started on and stop when it
/// changes, so that a search is abandoned as soon as the work it is based on is superseded.
#[derive(Default)]
struct Shared {
    extranonce1: Vec<u8>,
    extranonce2_size: usize,
    difficulty: f64,
    job: Option<Job>,
    generation: u64,
    closed: bool,
}

fn leaf(coinb1: &[u8], extranonce: &[u8], coinb2: &[u8]) -> [u8; 32] {
    let mut buf = Vec::with_capacity(1 + coinb1.len() + extranonce.len() + coinb2.len());
    buf.push(0x00);
    buf.extend_from_slice(coinb1);
    buf.extend_from_slice(extranonce);
    buf.extend_from_slice(coinb2);
    blake2b_256(&buf)
}

enum Outcome {
    Found(u32),
    Exhausted,
    Superseded,
}

fn mine(
    header: &[u8; HEADER_LEN],
    target: &target::Target,
    generation: &AtomicU64,
    job_generation: u64,
) -> Outcome {
    // The search is abandoned as soon as the job it is based on is superseded.
    let superseded = || generation.load(Ordering::Relaxed) != job_generation;
    match ratum::nonce::search(header, 32, blake2b_256, target, superseded) {
        Some(nonce) => Outcome::Found(nonce),
        None if generation.load(Ordering::SeqCst) != job_generation => Outcome::Superseded,
        None => Outcome::Exhausted,
    }
}

/// Reads the gateway's messages and records the latest job. Runs for as long as the
/// connection is open, so that a job arriving while the miner is hashing is read at once.
fn read_messages(
    stream: TcpStream,
    state: Arc<(Mutex<Shared>, Condvar)>,
    generation: Arc<AtomicU64>,
) {
    let (lock, waiting) = &*state;
    let mut r = BufReader::new(stream);
    let mut line = String::new();
    loop {
        line.clear();
        match r.read_line(&mut line) {
            Ok(0) | Err(_) => {
                println!("gateway closed the connection");
                lock.lock().expect("state").closed = true;
                waiting.notify_all();
                return;
            }
            Ok(_) => {}
        }
        let Ok(v) = serde_json::from_str::<serde_json::Value>(line.trim()) else { continue };

        if v["id"] == "1" && v["result"].is_array() {
            let res = &v["result"];
            let extranonce1 = hex::decode(res[1].as_str().unwrap_or("")).unwrap_or_default();
            let extranonce2_size = res[2].as_u64().unwrap_or(0) as usize;
            println!(
                "subscribed: extranonce1={} ({}B) extranonce2_size={extranonce2_size}",
                hex::encode(&extranonce1),
                extranonce1.len()
            );
            if extranonce1.len() + extranonce2_size != EXTRANONCE_LEN {
                println!(
                    "!! extranonce1 plus extranonce2_size totals {}B, not {EXTRANONCE_LEN}",
                    extranonce1.len() + extranonce2_size
                );
            }
            let mut s = lock.lock().expect("state");
            s.extranonce1 = extranonce1;
            s.extranonce2_size = extranonce2_size;
            continue;
        }

        match v["method"].as_str() {
            Some("mining.set_difficulty") => {
                let difficulty = v["params"][0].as_f64().unwrap_or(1.0);
                println!("set_difficulty {difficulty}");
                lock.lock().expect("state").difficulty = difficulty;
            }
            Some("mining.notify") => {
                let p = &v["params"];
                let prev = hex::decode(p[1].as_str().unwrap_or_default()).unwrap_or_default();
                let ntime_hex = p[7].as_str().unwrap_or_default().to_string();
                let ntime_raw = hex::decode(&ntime_hex).unwrap_or_default();
                let (Ok(prevhash), Ok(ntime)) =
                    (<[u8; 32]>::try_from(prev), <[u8; 8]>::try_from(ntime_raw))
                else {
                    println!("!! notify has a {}-char ntime or a bad prevhash", ntime_hex.len());
                    continue;
                };
                let job = Job {
                    job_id: p[0].as_str().unwrap_or_default().to_string(),
                    prevhash,
                    coinb1: hex::decode(p[2].as_str().unwrap_or_default()).unwrap_or_default(),
                    coinb2: hex::decode(p[3].as_str().unwrap_or_default()).unwrap_or_default(),
                    ntime,
                    ntime_hex,
                };
                let branches = p[4].as_array().map_or(0, |a| a.len());
                println!(
                    "job {} prev={} coinb1={}B coinb2={}B branches={branches}",
                    job.job_id,
                    &hex::encode(job.prevhash)[..16],
                    job.coinb1.len(),
                    job.coinb2.len(),
                );
                if !job.coinb2.is_empty() || branches != 0 {
                    println!(
                        "!! expected an empty coinb2 and no merkle branches for a version 2 job"
                    );
                }
                let mut s = lock.lock().expect("state");
                s.job = Some(job);
                s.generation += 1;
                generation.store(s.generation, Ordering::SeqCst);
                waiting.notify_all();
            }
            _ => {
                if v["id"].as_str().and_then(|s| s.parse::<u64>().ok()).unwrap_or(0) > 100 {
                    println!("submit response: {}", line.trim());
                }
            }
        }
    }
}

fn main() -> std::io::Result<()> {
    let mut args = std::env::args().skip(1);
    let addr = args.next().unwrap_or_else(|| "127.0.0.1:23334".to_string());
    let user =
        args.next().unwrap_or_else(|| "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4.sia".to_string());

    let stream = TcpStream::connect(&addr)?;
    let mut w = stream.try_clone()?;
    println!("connected to {addr}");

    writeln!(w, r#"{{"id":"1","method":"mining.subscribe","params":["sia-test-miner"]}}"#)?;
    writeln!(w, r#"{{"id":"2","method":"mining.authorize","params":["{user}","x"]}}"#)?;
    w.flush()?;

    let state =
        Arc::new((Mutex::new(Shared { difficulty: 1.0, ..Shared::default() }), Condvar::new()));
    let generation = Arc::new(AtomicU64::new(0));
    let reader = {
        let state = Arc::clone(&state);
        let generation = Arc::clone(&generation);
        std::thread::spawn(move || read_messages(stream, state, generation))
    };

    let (lock, waiting) = &*state;
    let mut submitted = 0;
    let mut last_generation = 0u64;

    loop {
        // Wait for a job newer than the one last mined, and for the extranonce1 and
        // extranonce2_size the subscribe response carries, without which the coinbase cannot be
        // assembled.
        let (job, difficulty, extranonce1, extranonce2_size, job_generation) = {
            let mut s = lock.lock().expect("state");
            while !s.closed
                && !(s.generation > last_generation && s.job.is_some() && s.extranonce2_size != 0)
            {
                s = waiting.wait(s).expect("state");
            }
            if s.closed {
                break;
            }
            (
                s.job.clone().expect("job"),
                s.difficulty,
                s.extranonce1.clone(),
                s.extranonce2_size,
                s.generation,
            )
        };
        last_generation = job_generation;

        let extranonce2 = vec![0x42u8; extranonce2_size];
        let mut extranonce = extranonce1;
        extranonce.extend_from_slice(&extranonce2);
        let hash1 = leaf(&job.coinb1, &extranonce, &job.coinb2);

        let mut header = [0u8; HEADER_LEN];
        header[0..32].copy_from_slice(&job.prevhash);
        header[40..48].copy_from_slice(&job.ntime);
        header[48..80].copy_from_slice(&hash1);

        // pdiff, as the gateway checks it (`get_target_from_diff`), not Stratum.md's bdiff-1
        // target.
        let t = target::target_for_difficulty(difficulty);
        println!("mining job {} at difficulty {difficulty}...", job.job_id);
        let started = std::time::Instant::now();
        match mine(&header, &t, &generation, job_generation) {
            Outcome::Found(nonce) => {
                let secs = started.elapsed().as_secs_f64();
                println!(
                    "found nonce {nonce:#010x} in {secs:.1}s ({:.0} MH/s)",
                    (nonce as f64 / secs) / 1e6
                );
                let mut nonce_field = [0u8; 8];
                nonce_field[0..4].copy_from_slice(&nonce.to_le_bytes());
                submitted += 1;
                writeln!(
                    w,
                    r#"{{"id":"{}","method":"mining.submit","params":["{}","{}","{}","{}","{}"]}}"#,
                    100 + submitted,
                    user,
                    job.job_id,
                    hex::encode(&extranonce2),
                    job.ntime_hex,
                    hex::encode(nonce_field),
                )?;
                w.flush()?;
                println!("submitted share for job {}", job.job_id);
            }
            Outcome::Exhausted => println!("nonce space exhausted without a share"),
            Outcome::Superseded => println!(
                "abandoned job {} after {:.1}s: the gateway sent a newer job",
                job.job_id,
                started.elapsed().as_secs_f64()
            ),
        }
    }

    reader.join().expect("reader thread");
    Ok(())
}
