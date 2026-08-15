//! CLI safety: flag combinations that must fail before any database connect.

use assert_cmd::Command;
use predicates::prelude::*;
use std::net::TcpListener;
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

fn cli() -> Command {
    Command::cargo_bin("redact-scan").unwrap()
}

#[test]
fn include_samples_with_report_url_exits_error_without_connect() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let addr = listener.local_addr().unwrap();
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        let mut accepted = 0u32;
        let start = std::time::Instant::now();
        while start.elapsed() < Duration::from_millis(400) {
            if listener.accept().is_ok() {
                accepted += 1;
            }
            thread::sleep(Duration::from_millis(10));
        }
        let _ = tx.send(accepted);
    });

    cli()
        .arg("--include-samples")
        .arg("--samples-out")
        .arg("/tmp/redact-scan-samples.json")
        .arg("--report-url")
        .arg(format!("http://{addr}/hook"))
        .arg("--url")
        .arg("postgres://nobody:should-not-connect@127.0.0.1:1/db")
        .assert()
        .failure()
        .code(2)
        .stderr(predicate::str::contains("--include-samples"));

    let accepted = rx.recv_timeout(Duration::from_secs(1)).unwrap_or(0);
    assert_eq!(accepted, 0, "must not open a TCP connection");
}

#[test]
fn help_mentions_read_only_scanner() {
    cli()
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("Read-only Postgres"));
}
