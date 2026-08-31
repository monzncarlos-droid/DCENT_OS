// SPDX-License-Identifier: GPL-3.0-or-later
//
// Local-only Stratum V1 fixture server for future Nano 3 shadow-TX tests.
//
// This binary is deliberately separate from `dcentrald-avalon`, is compiled
// only with the `nano3-shadow-sim` research feature, accepts numeric socket
// addresses only, and refuses every non-loopback bind. It never opens an
// outbound connection and contains no UART, USB, GPIO, watchdog, actuator, or
// hardware authority. Accepted shares are structurally checked only; this is
// not a proof-of-work or pool-validity oracle.

use std::net::SocketAddr;

use anyhow::{bail, Context, Result};
use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tracing::{info, warn};

const DEFAULT_BIND: &str = "127.0.0.1:33330";
const MAX_REQUEST_BYTES: usize = 16 * 1024;
const EXPECTED_WORKER: &str = "dcent.shadow";
const FIXTURE_JOB_ID: &str = "nano3-shadow-v1";
const FIXTURE_EXTRANONCE1: &str = "dce00001";
const FIXTURE_EXTRANONCE2_SIZE: u64 = 4;
const FIXTURE_DIFFICULTY: f64 = 1.0;
const FIXTURE_VERSION_MASK: &str = "1fffe000";

// A minimal deterministic coinbase transaction split around a four-byte
// extranonce1 and four-byte extranonce2. These are simulator inputs, not bytes
// recovered from stock and not a claim about any live pool job.
const FIXTURE_COINBASE1: &str = concat!(
    "01000000", // transaction version
    "01",       // one input
    "0000000000000000000000000000000000000000000000000000000000000000",
    "ffffffff", // coinbase prevout
    "0c",       // 12-byte scriptSig: prefix + extranonce1 + extranonce2
    "03000000"  // deterministic four-byte prefix
);
const FIXTURE_COINBASE2: &str = concat!(
    "ffffffff",         // input sequence
    "01",               // one output
    "0000000000000000", // zero-value simulator output
    "01",               // one-byte output script
    "51",               // OP_TRUE
    "00000000"          // locktime
);
const FIXTURE_PREVIOUS_HASH: &str =
    "0000000000000000000000000000000000000000000000000000000000000000";
const FIXTURE_VERSION: &str = "20000000";
const FIXTURE_NBITS: &str = "207fffff";
const FIXTURE_NTIME: &str = "65000000";

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
struct SessionReport {
    configured: bool,
    subscribed: bool,
    authorized: bool,
    job_sent: bool,
    structurally_accepted_submissions: u64,
}

#[derive(Debug)]
struct SimulatorConfig {
    bind: SocketAddr,
}

impl SimulatorConfig {
    fn parse_args() -> Result<Self> {
        let mut args = std::env::args().skip(1);
        let mut bind = DEFAULT_BIND
            .parse::<SocketAddr>()
            .expect("the compiled loopback default must be valid");
        while let Some(argument) = args.next() {
            match argument.as_str() {
                "--bind" => {
                    let value = args.next().context("--bind requires IP:PORT")?;
                    bind = value.parse::<SocketAddr>().with_context(|| {
                        format!("--bind requires a numeric IP:PORT, got `{value}`")
                    })?;
                }
                "--help" | "-h" => {
                    bail!(
                        "usage: nano3-stratum-sim [--bind LOOPBACK_IP:PORT]; default {DEFAULT_BIND}"
                    );
                }
                _ => bail!("unknown argument `{argument}`"),
            }
        }
        require_loopback(bind)?;
        Ok(Self { bind })
    }
}

fn require_loopback(address: SocketAddr) -> Result<()> {
    if !address.ip().is_loopback() {
        bail!(
            "refusing non-loopback Stratum simulator bind {address}; only 127.0.0.0/8 and ::1 are allowed"
        );
    }
    Ok(())
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let config = SimulatorConfig::parse_args()?;
    let listener = TcpListener::bind(config.bind)
        .await
        .with_context(|| format!("binding local simulator at {}", config.bind))?;
    let local = listener.local_addr()?;
    require_loopback(local)?;
    info!(
        bind = %local,
        worker = EXPECTED_WORKER,
        job_id = FIXTURE_JOB_ID,
        "Nano 3 Stratum simulator listening (local-only; no upstream or hardware authority)"
    );

    loop {
        let (stream, peer) = listener.accept().await?;
        if !peer.ip().is_loopback() {
            warn!(%peer, "refusing non-loopback simulator peer");
            continue;
        }
        tokio::spawn(async move {
            match serve_session(stream).await {
                Ok(report) => info!(%peer, ?report, "simulator session ended"),
                Err(error) => warn!(%peer, %error, "simulator session failed closed"),
            }
        });
    }
}

async fn serve_session(mut stream: TcpStream) -> Result<SessionReport> {
    let local = stream.local_addr()?;
    let peer = stream.peer_addr()?;
    require_loopback(local)?;
    require_loopback(peer)?;

    let mut report = SessionReport::default();
    loop {
        let Some(line) = read_bounded_line(&mut stream).await? else {
            return Ok(report);
        };
        let request: Value = serde_json::from_slice(&line).context("invalid JSON request")?;
        handle_request(&mut stream, &request, &mut report).await?;
    }
}

async fn read_bounded_line(stream: &mut TcpStream) -> Result<Option<Vec<u8>>> {
    let mut line = Vec::new();
    loop {
        let mut byte = [0u8; 1];
        match stream.read(&mut byte).await? {
            0 if line.is_empty() => return Ok(None),
            0 => bail!("connection ended inside a JSON line"),
            1 if byte[0] == b'\n' => return Ok(Some(line)),
            1 => {
                line.push(byte[0]);
                if line.len() > MAX_REQUEST_BYTES {
                    bail!("Stratum request exceeds {MAX_REQUEST_BYTES} bytes");
                }
            }
            _ => unreachable!("one-byte async read returned more than one byte"),
        }
    }
}

async fn handle_request(
    stream: &mut TcpStream,
    request: &Value,
    report: &mut SessionReport,
) -> Result<()> {
    let id = request.get("id").cloned().unwrap_or(Value::Null);
    let method = request
        .get("method")
        .and_then(Value::as_str)
        .context("request has no string method")?;
    let params = request
        .get("params")
        .and_then(Value::as_array)
        .context("request has no params array")?;

    match method {
        "mining.configure" => {
            report.configured = true;
            send_json(
                stream,
                &json!({
                    "id": id,
                    "result": {
                        "version-rolling": true,
                        "version-rolling.mask": FIXTURE_VERSION_MASK
                    },
                    "error": null
                }),
            )
            .await?;
        }
        "mining.subscribe" => {
            report.subscribed = true;
            send_json(
                stream,
                &json!({
                    "id": id,
                    "result": [
                        [
                            ["mining.set_difficulty", "dcent-nano3-shadow-v1"],
                            ["mining.notify", "dcent-nano3-shadow-v1"]
                        ],
                        FIXTURE_EXTRANONCE1,
                        FIXTURE_EXTRANONCE2_SIZE
                    ],
                    "error": null
                }),
            )
            .await?;
        }
        "mining.authorize" => {
            if !report.subscribed {
                return send_rpc_error(stream, id, 20, "subscribe required before authorize").await;
            }
            let worker = params.first().and_then(Value::as_str).unwrap_or_default();
            if worker != EXPECTED_WORKER {
                return send_rpc_error(stream, id, 24, "unexpected simulator worker").await;
            }
            report.authorized = true;
            send_json(stream, &json!({"id": id, "result": true, "error": null})).await?;
            send_json(
                stream,
                &json!({
                    "id": null,
                    "method": "mining.set_difficulty",
                    "params": [FIXTURE_DIFFICULTY]
                }),
            )
            .await?;
            send_json(
                stream,
                &json!({
                    "id": null,
                    "method": "mining.notify",
                    "params": [
                        FIXTURE_JOB_ID,
                        FIXTURE_PREVIOUS_HASH,
                        FIXTURE_COINBASE1,
                        FIXTURE_COINBASE2,
                        [],
                        FIXTURE_VERSION,
                        FIXTURE_NBITS,
                        FIXTURE_NTIME,
                        true
                    ]
                }),
            )
            .await?;
            report.job_sent = true;
        }
        "mining.extranonce.subscribe" | "mining.suggest_difficulty" => {
            send_json(stream, &json!({"id": id, "result": true, "error": null})).await?;
        }
        "mining.submit" => {
            if !report.authorized || !report.job_sent {
                return send_rpc_error(stream, id, 25, "authorized fixture job required").await;
            }
            match structurally_validate_submission(params) {
                Ok(()) => {
                    report.structurally_accepted_submissions += 1;
                    send_json(stream, &json!({"id": id, "result": true, "error": null})).await?;
                }
                Err(error) => {
                    send_rpc_error(stream, id, 26, &error.to_string()).await?;
                }
            }
        }
        _ => {
            send_rpc_error(
                stream,
                id,
                -32601,
                "method not available in local simulator",
            )
            .await?;
        }
    }
    Ok(())
}

fn structurally_validate_submission(params: &[Value]) -> Result<()> {
    if !(5..=6).contains(&params.len()) {
        bail!("submission requires five fields plus optional version bits");
    }
    if params[0].as_str() != Some(EXPECTED_WORKER) {
        bail!("submission worker does not match simulator fixture");
    }
    if params[1].as_str() != Some(FIXTURE_JOB_ID) {
        bail!("submission job id does not match active fixture");
    }
    require_lower_hex(params[2].as_str(), 8, "extranonce2")?;
    require_lower_hex(params[3].as_str(), 8, "ntime")?;
    require_lower_hex(params[4].as_str(), 8, "nonce")?;
    if params.len() == 6 {
        require_lower_hex(params[5].as_str(), 8, "version bits")?;
        let version_bits = u32::from_str_radix(params[5].as_str().unwrap(), 16)?;
        let mask = u32::from_str_radix(FIXTURE_VERSION_MASK, 16)?;
        if version_bits & !mask != 0 {
            bail!("version bits exceed negotiated simulator mask");
        }
    }
    Ok(())
}

fn require_lower_hex(value: Option<&str>, length: usize, field: &str) -> Result<()> {
    let value = value.with_context(|| format!("{field} is not a string"))?;
    if value.len() != length
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        bail!("{field} must be exactly {length} lowercase hex characters");
    }
    Ok(())
}

async fn send_json(stream: &mut TcpStream, value: &Value) -> Result<()> {
    let mut bytes = serde_json::to_vec(value)?;
    bytes.push(b'\n');
    stream.write_all(&bytes).await?;
    stream.flush().await?;
    Ok(())
}

async fn send_rpc_error(stream: &mut TcpStream, id: Value, code: i64, message: &str) -> Result<()> {
    send_json(
        stream,
        &json!({"id": id, "result": null, "error": [code, message, null]}),
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

    #[test]
    fn simulator_bind_is_loopback_only() {
        for accepted in ["127.0.0.1:1", "127.255.255.254:65535", "[::1]:1"] {
            require_loopback(accepted.parse().unwrap()).unwrap();
        }
        for refused in ["0.0.0.0:33330", "203.0.113.40:33330", "[::]:33330"] {
            let address = refused.parse().unwrap();
            let error = require_loopback(address).expect_err("non-loopback bind must fail closed");
            assert!(error.to_string().contains("refusing non-loopback"));
        }
    }

    async fn write_request(stream: &mut tokio::net::tcp::OwnedWriteHalf, value: Value) {
        let mut bytes = serde_json::to_vec(&value).unwrap();
        bytes.push(b'\n');
        stream.write_all(&bytes).await.unwrap();
    }

    async fn read_response(reader: &mut BufReader<tokio::net::tcp::OwnedReadHalf>) -> Value {
        let mut line = String::new();
        reader.read_line(&mut line).await.unwrap();
        assert!(!line.is_empty());
        serde_json::from_str(&line).unwrap()
    }

    #[tokio::test]
    async fn loopback_session_serves_deterministic_job_and_structural_submit() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            serve_session(stream).await.unwrap()
        });

        let client = TcpStream::connect(address).await.unwrap();
        let (read_half, mut write_half) = client.into_split();
        let mut reader = BufReader::new(read_half);

        write_request(
            &mut write_half,
            json!({"id": 1, "method": "mining.configure", "params": [[], {}]}),
        )
        .await;
        let configured = read_response(&mut reader).await;
        assert_eq!(
            configured["result"]["version-rolling.mask"],
            FIXTURE_VERSION_MASK
        );

        write_request(
            &mut write_half,
            json!({"id": 2, "method": "mining.subscribe", "params": ["test"]}),
        )
        .await;
        let subscribed = read_response(&mut reader).await;
        assert_eq!(subscribed["result"][1], FIXTURE_EXTRANONCE1);
        assert_eq!(subscribed["result"][2], FIXTURE_EXTRANONCE2_SIZE);

        write_request(
            &mut write_half,
            json!({
                "id": 3,
                "method": "mining.authorize",
                "params": [EXPECTED_WORKER, "x"]
            }),
        )
        .await;
        assert_eq!(read_response(&mut reader).await["result"], true);
        let difficulty = read_response(&mut reader).await;
        assert_eq!(difficulty["method"], "mining.set_difficulty");
        assert_eq!(difficulty["params"][0], FIXTURE_DIFFICULTY);
        let notify = read_response(&mut reader).await;
        assert_eq!(notify["method"], "mining.notify");
        assert_eq!(notify["params"][0], FIXTURE_JOB_ID);
        assert_eq!(notify["params"][2], FIXTURE_COINBASE1);
        assert_eq!(notify["params"][3], FIXTURE_COINBASE2);

        write_request(
            &mut write_half,
            json!({
                "id": 4,
                "method": "mining.submit",
                "params": [
                    EXPECTED_WORKER,
                    FIXTURE_JOB_ID,
                    "00000000",
                    FIXTURE_NTIME,
                    "00000000",
                    "00002000"
                ]
            }),
        )
        .await;
        assert_eq!(read_response(&mut reader).await["result"], true);

        drop(write_half);
        let report = server.await.unwrap();
        assert_eq!(
            report,
            SessionReport {
                configured: true,
                subscribed: true,
                authorized: true,
                job_sent: true,
                structurally_accepted_submissions: 1,
            }
        );
    }

    #[test]
    fn submission_validation_is_strict_but_not_a_pow_claim() {
        let valid = vec![
            json!(EXPECTED_WORKER),
            json!(FIXTURE_JOB_ID),
            json!("00000000"),
            json!(FIXTURE_NTIME),
            json!("deadbeef"),
        ];
        structurally_validate_submission(&valid).unwrap();

        let mut wrong_job = valid.clone();
        wrong_job[1] = json!("other");
        assert!(structurally_validate_submission(&wrong_job).is_err());

        let mut uppercase_nonce = valid;
        uppercase_nonce[4] = json!("DEADBEEF");
        assert!(structurally_validate_submission(&uppercase_nonce).is_err());
    }
}
