//! One cause, one line (T-809, after podnet's QA round, PodUtils/podnet#649):
//! `podssh ssh` through podssh's own relay role to a port where nothing
//! listens ends with 255 within its limit, and says the cause once. The
//! layer's road says that the relay could not reach the target; the SSH
//! client's own words of the closed connection ("the connection closed
//! unexpectedly") are no second line. The planted defect: both lines, as
//! before. It says that it did not run where this host has no openssl for
//! the role's certificate.

mod ssh_harness;
mod throughput_harness;

use std::io::Read;
use std::process::Stdio;
use std::time::{Duration, Instant};

use throughput_harness::{Cell, Session};

const LIMIT: Duration = Duration::from_secs(60);

/// A port of the loopback where nothing listens: one bound, then let go.
fn closed_port() -> u16 {
    let socket = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    socket.local_addr().unwrap().port()
}

#[test]
fn a_refused_target_is_one_line_and_255() {
    let s = Session::start("error-lines");
    let cell = match Cell::podssh_relay(&s, "podssh's relay role", &["--allow-private"]) {
        Ok(cell) => cell,
        Err((_, why)) => {
            eprintln!("did not run: {why}");
            return;
        }
    };
    let ca = cell.args.iter().position(|a| a == "--ca-file").map(|i| cell.args[i + 1].clone()).unwrap();
    let mut args = cell.args.clone();
    let port = args.iter().position(|a| a == "-p").unwrap() + 1;
    args[port] = closed_port().to_string();
    args.push("true".into());
    let mut child =
        s.stand_in(&args, &ca).stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::piped()).spawn().unwrap();
    let mut stderr = child.stderr.take().unwrap();
    let said = std::thread::spawn(move || {
        let mut text = String::new();
        let _ = stderr.read_to_string(&mut text);
        text
    });
    let started = Instant::now();
    let code = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status.code();
        }
        if started.elapsed() > LIMIT {
            let _ = child.kill();
            panic!("podssh ssh to a closed port did not end within {LIMIT:?}");
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    let err = said.join().unwrap();
    assert_eq!(code, Some(255), "{err}");
    let lines: Vec<&str> = err.lines().filter(|l| !l.trim().is_empty()).collect();
    assert_eq!(lines.len(), 1, "one cause, one line: {err}");
    assert!(lines[0].contains("could not reach") && lines[0].contains("refused"), "{err}");
}
