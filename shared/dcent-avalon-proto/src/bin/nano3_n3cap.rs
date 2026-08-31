// SPDX-License-Identifier: GPL-3.0-or-later
//
// File-only Saleae analyzer export conversion for Nano 3 capture evidence.
// This binary contains no serial, USB, network, process-control, or TX path.

use std::collections::BTreeMap;
use std::env;
use std::ffi::OsStr;
use std::fmt::Write as _;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Cursor, Read, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use dcent_avalon_proto::nano3_uart::{decode_native_uart_envelope, StockNextPollAction};
use dcent_avalon_proto::nano3_uart_transcript::{
    assemble_capture_artifact, decode_capture_artifact, extract_capture_artifact, CaptureByteChunk,
    CaptureDirection, DecodedCaptureArtifact, Nano3CaptureArtifactError, Nano3CaptureAssemblyError,
    Nano3TranscriptError, ObservedPollSelector, PollCaptureOutcome, CAPTURE_ARTIFACT_MAX_LEN,
    CAPTURE_ASSEMBLY_MAX_RAW_BYTES,
};
use dcent_avalon_proto::nano3_uart_transcript::{validate_init_capture, validate_poll_capture};
use sha2::{Digest, Sha256};

const NANO3_UART_BAUD: u128 = 115_200;
const PICOSECONDS_PER_SECOND: u128 = 1_000_000_000_000;
const PICOSECONDS_PER_MICROSECOND: i128 = 1_000_000;
const UART_8N1_BITS_PER_BYTE: u128 = 10;
const UART_BYTE_DURATION_PS: i128 =
    (UART_8N1_BITS_PER_BYTE * PICOSECONDS_PER_SECOND).div_ceil(NANO3_UART_BAUD) as i128;
const MAX_ANALYZER_CSV_BYTES: usize = 128 * 1024 * 1024;
const SOURCE_HASH_BUFFER_LEN: usize = 1024 * 1024;

const USAGE: &str = r#"nano3-n3cap - file-only Nano 3 Saleae-to-.n3cap converter

USAGE:
  nano3-n3cap assemble-saleae \
    --source-capture CAPTURE.sal \
    --host-to-controller HOST.csv \
    --controller-to-host CONTROLLER.csv \
    --capture-end-s SECONDS \
    --time-semantics start|end \
    --data-radix hex|decimal \
    --output CAPTURE.n3cap

  nano3-n3cap verify --input CAPTURE.n3cap

  nano3-n3cap inventory --input CAPTURE.n3cap

  nano3-n3cap extract \
    --input CAPTURE.n3cap \
    --first-event INDEX \
    --event-count COUNT \
    --output EXCHANGE.n3cap

  nano3-n3cap validate-init \
    --input INIT.n3cap \
    --requested-work-level LEVEL

  nano3-n3cap validate-poll --input POLL.n3cap

The two CSVs must be Async Serial analyzer exports from the same .sal capture.
Nano 3 framing is fixed at 115200 baud, 8N1. Inputs must be regular, non-symlink
files; output is create-new and is never overwritten. No device is opened.
Inventory prints zero-based event indices and bounded frame metadata without
payload bytes. Extract copies one contiguous range and derives a conservative
end boundary from the source; equal-microsecond boundaries fail closed.
Semantic validation requires an artifact scoped to exactly one init or poll
exchange; trailing events fail closed. Reports never authorize TX or a device.
"#;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TimeSemantics {
    Start,
    End,
}

impl TimeSemantics {
    fn parse(raw: &str) -> Result<Self, CliError> {
        match raw {
            "start" => Ok(Self::Start),
            "end" => Ok(Self::End),
            _ => Err(CliError::Usage(
                "--time-semantics must be exactly start or end".into(),
            )),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DataRadix {
    Hex,
    Decimal,
}

impl DataRadix {
    fn parse(raw: &str) -> Result<Self, CliError> {
        match raw {
            "hex" => Ok(Self::Hex),
            "decimal" => Ok(Self::Decimal),
            _ => Err(CliError::Usage(
                "--data-radix must be exactly hex or decimal".into(),
            )),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct AssembleArgs {
    source_capture: PathBuf,
    host_csv: PathBuf,
    controller_csv: PathBuf,
    capture_end_s: String,
    time_semantics: TimeSemantics,
    data_radix: DataRadix,
    output: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Command {
    Assemble(AssembleArgs),
    Verify {
        input: PathBuf,
    },
    Inventory {
        input: PathBuf,
    },
    Extract {
        input: PathBuf,
        first_event: usize,
        event_count: usize,
        output: PathBuf,
    },
    ValidateInit {
        input: PathBuf,
        requested_work_level: u8,
    },
    ValidatePoll {
        input: PathBuf,
    },
    Help,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct TimedByte {
    completion_ps: i128,
    direction: CaptureDirection,
    byte: u8,
    source_row: usize,
}

#[derive(Debug, thiserror::Error)]
enum CliError {
    #[error("{0}")]
    Usage(String),

    #[error("{role} path must end in .{extension}: {path}")]
    Extension {
        role: &'static str,
        extension: &'static str,
        path: PathBuf,
    },

    #[error("{role} must not be a symbolic link: {path}")]
    Symlink { role: &'static str, path: PathBuf },

    #[error("{role} is not a regular file: {path}")]
    NotRegularFile { role: &'static str, path: PathBuf },

    #[error("{role} exceeds the {maximum}-byte offline input limit: {observed} bytes")]
    FileTooLong {
        role: &'static str,
        observed: u64,
        maximum: usize,
    },

    #[error("host-to-controller and controller-to-host CSV paths must differ")]
    SameDirectionFile,

    #[error("source capture is not a Saleae .sal ZIP archive: {0}")]
    BadSaleaeArchive(PathBuf),

    #[error("output already exists; refusing to overwrite it: {0}")]
    OutputExists(PathBuf),

    #[error("output parent is not a directory: {0}")]
    OutputParentNotDirectory(PathBuf),

    #[error("{role} path uses a Windows device namespace or reserved device name: {path}")]
    UnsafePath { role: &'static str, path: PathBuf },

    #[error("{operation} {path}: {source}")]
    Io {
        operation: &'static str,
        path: PathBuf,
        #[source]
        source: io::Error,
    },

    #[error("parse {role} CSV {path}: {source}")]
    Csv {
        role: &'static str,
        path: PathBuf,
        #[source]
        source: csv::Error,
    },

    #[error("{role} CSV has no header row")]
    MissingHeaders { role: &'static str },

    #[error("{role} CSV has no supported {column_kind} column; headers: {headers:?}")]
    MissingColumn {
        role: &'static str,
        column_kind: &'static str,
        headers: Vec<String>,
    },

    #[error("{role} CSV has ambiguous {column_kind} columns: {columns:?}")]
    AmbiguousColumn {
        role: &'static str,
        column_kind: &'static str,
        columns: Vec<String>,
    },

    #[error("{role} CSV row {row} has an empty {column_kind} field")]
    EmptyField {
        role: &'static str,
        row: usize,
        column_kind: &'static str,
    },

    #[error("{role} CSV row {row} timestamp {value:?} is invalid: {reason}")]
    Timestamp {
        role: &'static str,
        row: usize,
        value: String,
        reason: String,
    },

    #[error("{role} CSV row {row} data {value:?} is not one {radix} byte")]
    Data {
        role: &'static str,
        row: usize,
        value: String,
        radix: &'static str,
    },

    #[error("{role} CSV contains no UART bytes")]
    EmptyDirection { role: &'static str },

    #[error("{role} CSV row {row} does not move strictly forward in byte-completion time")]
    NonIncreasingTime { role: &'static str, row: usize },

    #[error("combined analyzer exports contain more than {maximum} UART bytes")]
    TooManyBytes { maximum: usize },

    #[error(
        "cross-direction byte order is ambiguous at {completion_ps} ps (rows {first_row} and {second_row})"
    )]
    AmbiguousOrder {
        completion_ps: i128,
        first_row: usize,
        second_row: usize,
    },

    #[error("capture end {capture_end_ps} ps precedes the final byte at {last_byte_ps} ps")]
    CaptureEndBeforeLastByte {
        capture_end_ps: i128,
        last_byte_ps: i128,
    },

    #[error("normalized capture time does not fit in unsigned microseconds")]
    TimeRange,

    #[error(transparent)]
    Assembly(#[from] Nano3CaptureAssemblyError),

    #[error(transparent)]
    Artifact(#[from] Nano3CaptureArtifactError),

    #[error(transparent)]
    Transcript(#[from] Nano3TranscriptError),
}

fn main() -> ExitCode {
    match run(env::args().skip(1)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("nano3-n3cap: {error}");
            ExitCode::from(2)
        }
    }
}

fn run(args: impl IntoIterator<Item = String>) -> Result<(), CliError> {
    match parse_command(args)? {
        Command::Help => {
            print!("{USAGE}");
            Ok(())
        }
        Command::Assemble(args) => run_assemble(&args),
        Command::Verify { input } => run_verify(&input),
        Command::Inventory { input } => run_inventory(&input),
        Command::Extract {
            input,
            first_event,
            event_count,
            output,
        } => run_extract(&input, first_event, event_count, &output),
        Command::ValidateInit {
            input,
            requested_work_level,
        } => run_validate_init(&input, requested_work_level),
        Command::ValidatePoll { input } => run_validate_poll(&input),
    }
}

fn parse_command(args: impl IntoIterator<Item = String>) -> Result<Command, CliError> {
    let mut args = args.into_iter();
    let Some(subcommand) = args.next() else {
        return Ok(Command::Help);
    };
    if matches!(subcommand.as_str(), "-h" | "--help" | "help") {
        return Ok(Command::Help);
    }
    let options = parse_options(args)?;
    match subcommand.as_str() {
        "assemble-saleae" => {
            reject_unknown(
                &options,
                &[
                    "--source-capture",
                    "--host-to-controller",
                    "--controller-to-host",
                    "--capture-end-s",
                    "--time-semantics",
                    "--data-radix",
                    "--output",
                ],
            )?;
            Ok(Command::Assemble(AssembleArgs {
                source_capture: PathBuf::from(required(&options, "--source-capture")?),
                host_csv: PathBuf::from(required(&options, "--host-to-controller")?),
                controller_csv: PathBuf::from(required(&options, "--controller-to-host")?),
                capture_end_s: required(&options, "--capture-end-s")?.to_owned(),
                time_semantics: TimeSemantics::parse(required(&options, "--time-semantics")?)?,
                data_radix: DataRadix::parse(required(&options, "--data-radix")?)?,
                output: PathBuf::from(required(&options, "--output")?),
            }))
        }
        "verify" => {
            reject_unknown(&options, &["--input"])?;
            Ok(Command::Verify {
                input: PathBuf::from(required(&options, "--input")?),
            })
        }
        "inventory" => {
            reject_unknown(&options, &["--input"])?;
            Ok(Command::Inventory {
                input: PathBuf::from(required(&options, "--input")?),
            })
        }
        "extract" => {
            reject_unknown(
                &options,
                &["--input", "--first-event", "--event-count", "--output"],
            )?;
            Ok(Command::Extract {
                input: PathBuf::from(required(&options, "--input")?),
                first_event: parse_event_number(&options, "--first-event")?,
                event_count: parse_event_number(&options, "--event-count")?,
                output: PathBuf::from(required(&options, "--output")?),
            })
        }
        "validate-init" => {
            reject_unknown(&options, &["--input", "--requested-work-level"])?;
            let raw_level = required(&options, "--requested-work-level")?;
            let requested_work_level = raw_level.parse::<u8>().map_err(|_| {
                CliError::Usage(format!(
                    "--requested-work-level must be an unsigned byte, got {raw_level:?}"
                ))
            })?;
            Ok(Command::ValidateInit {
                input: PathBuf::from(required(&options, "--input")?),
                requested_work_level,
            })
        }
        "validate-poll" => {
            reject_unknown(&options, &["--input"])?;
            Ok(Command::ValidatePoll {
                input: PathBuf::from(required(&options, "--input")?),
            })
        }
        _ => Err(CliError::Usage(format!(
            "unknown subcommand {subcommand:?}; expected assemble-saleae, verify, inventory, extract, validate-init, or validate-poll"
        ))),
    }
}

fn parse_options(
    args: impl IntoIterator<Item = String>,
) -> Result<BTreeMap<String, String>, CliError> {
    let mut args = args.into_iter();
    let mut options = BTreeMap::new();
    while let Some(option) = args.next() {
        if !option.starts_with("--") {
            return Err(CliError::Usage(format!(
                "unexpected positional argument {option:?}"
            )));
        }
        let value = args
            .next()
            .ok_or_else(|| CliError::Usage(format!("missing value for {option}")))?;
        if value.starts_with("--") {
            return Err(CliError::Usage(format!("missing value for {option}")));
        }
        if options.insert(option.clone(), value).is_some() {
            return Err(CliError::Usage(format!("duplicate option {option}")));
        }
    }
    Ok(options)
}

fn required<'a>(
    options: &'a BTreeMap<String, String>,
    name: &'static str,
) -> Result<&'a str, CliError> {
    options
        .get(name)
        .map(String::as_str)
        .ok_or_else(|| CliError::Usage(format!("missing required option {name}")))
}

fn parse_event_number(
    options: &BTreeMap<String, String>,
    name: &'static str,
) -> Result<usize, CliError> {
    let raw = required(options, name)?;
    if raw.is_empty()
        || !raw.bytes().all(|byte| byte.is_ascii_digit())
        || (raw.len() > 1 && raw.starts_with('0'))
    {
        return Err(CliError::Usage(format!(
            "{name} must be a canonical unsigned decimal integer, got {raw:?}"
        )));
    }
    raw.parse::<usize>().map_err(|_| {
        CliError::Usage(format!(
            "{name} is outside the supported event-index range: {raw:?}"
        ))
    })
}

fn reject_unknown(options: &BTreeMap<String, String>, allowed: &[&str]) -> Result<(), CliError> {
    if let Some(name) = options
        .keys()
        .find(|name| !allowed.contains(&name.as_str()))
    {
        return Err(CliError::Usage(format!("unknown option {name}")));
    }
    Ok(())
}

fn run_assemble(args: &AssembleArgs) -> Result<(), CliError> {
    require_extension(&args.source_capture, "sal", "source capture")?;
    require_extension(&args.host_csv, "csv", "host-to-controller CSV")?;
    require_extension(&args.controller_csv, "csv", "controller-to-host CSV")?;
    require_extension(&args.output, "n3cap", "output")?;
    if args.host_csv == args.controller_csv {
        return Err(CliError::SameDirectionFile);
    }
    prepare_output(&args.output)?;

    validate_saleae_archive(&args.source_capture)?;
    let source_capture_sha256 = hash_regular_file(&args.source_capture, "source capture")?;
    let (host_bytes, host_sha256) = read_bounded_regular_file(
        &args.host_csv,
        "host-to-controller CSV",
        MAX_ANALYZER_CSV_BYTES,
    )?;
    let (controller_bytes, controller_sha256) = read_bounded_regular_file(
        &args.controller_csv,
        "controller-to-host CSV",
        MAX_ANALYZER_CSV_BYTES,
    )?;

    let host = parse_saleae_csv(
        Cursor::new(host_bytes),
        &args.host_csv,
        "host-to-controller",
        CaptureDirection::HostToController,
        args.time_semantics,
        args.data_radix,
    )?;
    let controller = parse_saleae_csv(
        Cursor::new(controller_bytes),
        &args.controller_csv,
        "controller-to-host",
        CaptureDirection::ControllerToHost,
        args.time_semantics,
        args.data_radix,
    )?;
    let capture_end_ps =
        parse_seconds_to_ps(&args.capture_end_s).map_err(|reason| CliError::Timestamp {
            role: "capture end",
            row: 0,
            value: args.capture_end_s.clone(),
            reason,
        })?;
    let (records, ended_us, origin_ps) = merge_and_normalize(host, controller, capture_end_ps)?;
    let chunks: Vec<_> = records
        .iter()
        .map(|record| CaptureByteChunk {
            elapsed_us: record.elapsed_us,
            direction: record.direction,
            bytes: std::slice::from_ref(&record.byte),
        })
        .collect();
    let artifact = assemble_capture_artifact(&chunks, ended_us)?;
    let decoded = decode_capture_artifact(&artifact)?;
    write_create_new(&args.output, &artifact)?;

    let artifact_sha256 = sha256_bytes(&artifact);
    let host_frames = decoded
        .events()
        .iter()
        .filter(|event| event.direction == CaptureDirection::HostToController)
        .count();
    let controller_frames = decoded.events().len() - host_frames;
    println!("source_capture_sha256={source_capture_sha256}");
    println!("host_csv_sha256={host_sha256}");
    println!("controller_csv_sha256={controller_sha256}");
    println!("artifact_sha256={artifact_sha256}");
    println!("transcript_digest={}", hex(decoded.digest()));
    println!("origin_ps={origin_ps}");
    println!("ended_us={}", decoded.ended_us());
    println!("host_to_controller_frames={host_frames}");
    println!("controller_to_host_frames={controller_frames}");
    println!("provenance_binding=operator_export_claim_not_cryptographic");
    Ok(())
}

fn run_verify(input: &Path) -> Result<(), CliError> {
    require_extension(input, "n3cap", "input artifact")?;
    let (bytes, artifact_sha256) =
        read_bounded_regular_file(input, "input artifact", CAPTURE_ARTIFACT_MAX_LEN)?;
    let decoded = decode_capture_artifact(&bytes)?;
    let host_frames = decoded
        .events()
        .iter()
        .filter(|event| event.direction == CaptureDirection::HostToController)
        .count();
    println!("artifact_sha256={artifact_sha256}");
    println!("transcript_digest={}", hex(decoded.digest()));
    println!("ended_us={}", decoded.ended_us());
    println!("events={}", decoded.events().len());
    println!("host_to_controller_frames={host_frames}");
    println!(
        "controller_to_host_frames={}",
        decoded.events().len() - host_frames
    );
    Ok(())
}

fn run_inventory(input: &Path) -> Result<(), CliError> {
    require_extension(input, "n3cap", "input artifact")?;
    let (bytes, artifact_sha256) =
        read_bounded_regular_file(input, "input artifact", CAPTURE_ARTIFACT_MAX_LEN)?;
    let decoded = decode_capture_artifact(&bytes)?;
    print!("{}", inventory_report(&decoded, &artifact_sha256));
    Ok(())
}

fn inventory_report(decoded: &DecodedCaptureArtifact<'_>, artifact_sha256: &str) -> String {
    let mut report = String::new();
    writeln!(&mut report, "artifact_sha256={artifact_sha256}")
        .expect("writing to String cannot fail");
    writeln!(&mut report, "transcript_digest={}", hex(decoded.digest()))
        .expect("writing to String cannot fail");
    writeln!(&mut report, "ended_us={}", decoded.ended_us())
        .expect("writing to String cannot fail");
    writeln!(&mut report, "events={}", decoded.events().len())
        .expect("writing to String cannot fail");
    for (event_index, event) in decoded.events().iter().enumerate() {
        let envelope = decode_native_uart_envelope(event.bytes)
            .expect("canonical artifact already validated every envelope");
        writeln!(
            &mut report,
            "event[{event_index}]=elapsed_us:{} direction:{} packet_type:0x{:02x} option:{} index:{} count:{} payload_len:{} frame_len:{} frame_sha256:{}",
            event.elapsed_us,
            match event.direction {
                CaptureDirection::HostToController => "host-to-controller",
                CaptureDirection::ControllerToHost => "controller-to-host",
            },
            envelope.packet_type,
            envelope.option,
            envelope.index,
            envelope.count,
            envelope.payload.len(),
            event.bytes.len(),
            sha256_bytes(event.bytes),
        )
        .expect("writing to String cannot fail");
    }
    report.push_str("authorizes_transmit=false\nauthorizes_device=false\n");
    report
}

fn run_extract(
    input: &Path,
    first_event: usize,
    event_count: usize,
    output: &Path,
) -> Result<(), CliError> {
    require_extension(input, "n3cap", "input artifact")?;
    require_extension(output, "n3cap", "output artifact")?;
    let (source_bytes, source_artifact_sha256) =
        read_bounded_regular_file(input, "input artifact", CAPTURE_ARTIFACT_MAX_LEN)?;
    let source = decode_capture_artifact(&source_bytes)?;
    let extracted_bytes = extract_capture_artifact(source.window(), first_event, event_count)?;
    let extracted = decode_capture_artifact(&extracted_bytes)?;
    let end_exclusive = first_event
        .checked_add(event_count)
        .expect("successful extraction proved range addition");
    let reaches_source_end = end_exclusive == source.events().len();

    prepare_output(output)?;
    write_create_new(output, &extracted_bytes)?;

    println!("source_artifact_sha256={source_artifact_sha256}");
    println!("source_transcript_digest={}", hex(source.digest()));
    println!("source_events={}", source.events().len());
    println!("first_event={first_event}");
    println!("event_count={event_count}");
    println!("source_end_exclusive={end_exclusive}");
    println!(
        "end_boundary={}",
        if reaches_source_end {
            "source-capture-end"
        } else {
            "last-selected-event-no-timeout-proof"
        }
    );
    if reaches_source_end {
        println!("next_source_event=none");
    } else {
        println!("next_source_event={end_exclusive}");
    }
    println!("output_artifact_sha256={}", sha256_bytes(&extracted_bytes));
    println!("output_transcript_digest={}", hex(extracted.digest()));
    println!("output_ended_us={}", extracted.ended_us());
    println!("authorizes_transmit=false");
    println!("authorizes_device=false");
    Ok(())
}

fn run_validate_init(input: &Path, requested_work_level: u8) -> Result<(), CliError> {
    require_extension(input, "n3cap", "init artifact")?;
    let (bytes, artifact_sha256) =
        read_bounded_regular_file(input, "init artifact", CAPTURE_ARTIFACT_MAX_LEN)?;
    let decoded = decode_capture_artifact(&bytes)?;
    let report = validate_init_capture(decoded.window(), requested_work_level)?;
    println!("artifact_sha256={artifact_sha256}");
    println!("validated_contract=stock-init");
    println!("transcript_digest={}", hex(report.digest()));
    println!("detect_attempts={}", report.detect_attempts());
    println!("sync_attempts={}", report.sync_attempts());
    println!("requested_work_level={requested_work_level}");
    println!(
        "detected_work_level_maximum={}",
        report.detected_work_level_maximum()
    );
    println!("selected_work_level={}", report.selected_work_level());
    println!("authorizes_transmit=false");
    println!("authorizes_device=false");
    Ok(())
}

fn run_validate_poll(input: &Path) -> Result<(), CliError> {
    require_extension(input, "n3cap", "poll artifact")?;
    let (bytes, artifact_sha256) =
        read_bounded_regular_file(input, "poll artifact", CAPTURE_ARTIFACT_MAX_LEN)?;
    let decoded = decode_capture_artifact(&bytes)?;
    let report = validate_poll_capture(decoded.window())?;
    println!("artifact_sha256={artifact_sha256}");
    println!("validated_contract=stock-poll");
    println!("transcript_digest={}", hex(report.digest()));
    println!(
        "selector={}",
        match report.selector() {
            ObservedPollSelector::ReadOnly => "read-only",
            ObservedPollSelector::StatefulReset => "stateful-reset-observed",
        }
    );
    println!("attempts={}", report.attempts());
    match report.outcome() {
        PollCaptureOutcome::Response {
            packet_type,
            next_stock_action,
        } => {
            println!("outcome=response");
            println!("response_type=0x{:02x}", packet_type as u8);
            println!(
                "next_stock_action={}",
                match next_stock_action {
                    None => "none",
                    Some(StockNextPollAction::ReadOnlySelector) => "read-only-selector",
                    Some(StockNextPollAction::StatefulResetSelector) => {
                        "stateful-reset-selector-observed"
                    }
                }
            );
        }
        PollCaptureOutcome::ExhaustedWithoutResponse => {
            println!("outcome=exhausted-without-response");
            println!("response_type=none");
            println!("next_stock_action=none");
        }
    }
    println!("authorizes_transmit={}", report.authorizes_transmit());
    println!("authorizes_device=false");
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct NormalizedByte {
    elapsed_us: u64,
    direction: CaptureDirection,
    byte: u8,
}

fn parse_saleae_csv<R: Read>(
    reader: R,
    path: &Path,
    role: &'static str,
    direction: CaptureDirection,
    time_semantics: TimeSemantics,
    data_radix: DataRadix,
) -> Result<Vec<TimedByte>, CliError> {
    let mut reader = csv::ReaderBuilder::new()
        .trim(csv::Trim::All)
        .flexible(false)
        .from_reader(reader);
    let headers = reader
        .headers()
        .map_err(|source| CliError::Csv {
            role,
            path: path.to_path_buf(),
            source,
        })?
        .clone();
    if headers.is_empty() {
        return Err(CliError::MissingHeaders { role });
    }
    let time_candidates: &[&str] = match time_semantics {
        TimeSemantics::Start => &["start time [s]", "time [s]", "time"],
        TimeSemantics::End => &["end time [s]", "time [s]", "time"],
    };
    let time_index = resolve_column(&headers, role, "time", time_candidates)?;
    let data_index = resolve_column(&headers, role, "data", &["data", "data (hex)", "value"])?;

    let mut decoded = Vec::new();
    let mut previous_completion = None;
    for (record_index, record) in reader.records().enumerate() {
        let row = record_index + 2;
        let record = record.map_err(|source| CliError::Csv {
            role,
            path: path.to_path_buf(),
            source,
        })?;
        let time_raw = record.get(time_index).unwrap_or_default().trim();
        if time_raw.is_empty() {
            return Err(CliError::EmptyField {
                role,
                row,
                column_kind: "time",
            });
        }
        let mut completion_ps =
            parse_seconds_to_ps(time_raw).map_err(|reason| CliError::Timestamp {
                role,
                row,
                value: time_raw.to_owned(),
                reason,
            })?;
        if time_semantics == TimeSemantics::Start {
            completion_ps = completion_ps
                .checked_add(UART_BYTE_DURATION_PS)
                .ok_or(CliError::TimeRange)?;
        }
        if previous_completion.is_some_and(|previous| completion_ps <= previous) {
            return Err(CliError::NonIncreasingTime { role, row });
        }
        previous_completion = Some(completion_ps);

        let data_raw = record.get(data_index).unwrap_or_default().trim();
        if data_raw.is_empty() {
            return Err(CliError::EmptyField {
                role,
                row,
                column_kind: "data",
            });
        }
        let byte = parse_byte(data_raw, data_radix).ok_or_else(|| CliError::Data {
            role,
            row,
            value: data_raw.to_owned(),
            radix: match data_radix {
                DataRadix::Hex => "hexadecimal",
                DataRadix::Decimal => "decimal",
            },
        })?;
        if decoded.len() == CAPTURE_ASSEMBLY_MAX_RAW_BYTES {
            return Err(CliError::TooManyBytes {
                maximum: CAPTURE_ASSEMBLY_MAX_RAW_BYTES,
            });
        }
        decoded.push(TimedByte {
            completion_ps,
            direction,
            byte,
            source_row: row,
        });
    }
    if decoded.is_empty() {
        return Err(CliError::EmptyDirection { role });
    }
    Ok(decoded)
}

fn resolve_column(
    headers: &csv::StringRecord,
    role: &'static str,
    column_kind: &'static str,
    candidates: &[&str],
) -> Result<usize, CliError> {
    let matches: Vec<_> = headers
        .iter()
        .enumerate()
        .filter(|(_, header)| candidates.contains(&header.trim().to_ascii_lowercase().as_str()))
        .collect();
    match matches.as_slice() {
        [(index, _)] => Ok(*index),
        [] => Err(CliError::MissingColumn {
            role,
            column_kind,
            headers: headers.iter().map(str::to_owned).collect(),
        }),
        _ => Err(CliError::AmbiguousColumn {
            role,
            column_kind,
            columns: matches
                .into_iter()
                .map(|(_, header)| header.to_owned())
                .collect(),
        }),
    }
}

fn parse_byte(raw: &str, radix: DataRadix) -> Option<u8> {
    match radix {
        DataRadix::Hex => {
            let digits = raw
                .strip_prefix("0x")
                .or_else(|| raw.strip_prefix("0X"))
                .unwrap_or(raw);
            if digits.is_empty() || digits.len() > 2 {
                return None;
            }
            u8::from_str_radix(digits, 16).ok()
        }
        DataRadix::Decimal => {
            if raw.is_empty() || !raw.bytes().all(|byte| byte.is_ascii_digit()) {
                return None;
            }
            raw.parse().ok()
        }
    }
}

fn parse_seconds_to_ps(raw: &str) -> Result<i128, String> {
    let raw = raw.trim();
    if raw.is_empty() {
        return Err("empty decimal".into());
    }
    let (negative, unsigned) = match raw.as_bytes()[0] {
        b'-' => (true, &raw[1..]),
        b'+' => (false, &raw[1..]),
        _ => (false, raw),
    };
    if unsigned.is_empty() {
        return Err("missing mantissa".into());
    }
    let mut exponent_split = unsigned.split(['e', 'E']);
    let mantissa = exponent_split.next().expect("nonempty split");
    let exponent = match exponent_split.next() {
        Some(value) => value
            .parse::<i32>()
            .map_err(|_| "invalid base-10 exponent".to_owned())?,
        None => 0,
    };
    if exponent_split.next().is_some() {
        return Err("multiple exponent markers".into());
    }
    if !(-30..=30).contains(&exponent) {
        return Err("exponent outside supported -30..30 range".into());
    }

    let mut coefficient = 0u128;
    let mut fractional_digits = 0i32;
    let mut saw_digit = false;
    let mut saw_decimal = false;
    for byte in mantissa.bytes() {
        match byte {
            b'0'..=b'9' => {
                saw_digit = true;
                coefficient = coefficient
                    .checked_mul(10)
                    .and_then(|value| value.checked_add(u128::from(byte - b'0')))
                    .ok_or_else(|| "mantissa is too large".to_owned())?;
                if saw_decimal {
                    fractional_digits += 1;
                }
            }
            b'.' if !saw_decimal => saw_decimal = true,
            _ => return Err("mantissa must contain only decimal digits and one dot".into()),
        }
    }
    if !saw_digit {
        return Err("mantissa has no digits".into());
    }

    let power = 12 + exponent - fractional_digits;
    let magnitude = if power >= 0 {
        coefficient
            .checked_mul(pow10(power as u32)?)
            .ok_or_else(|| "timestamp is too large".to_owned())?
    } else {
        let divisor = pow10((-power) as u32)?;
        let quotient = coefficient / divisor;
        let remainder = coefficient % divisor;
        quotient
            .checked_add(u128::from(remainder >= divisor.div_ceil(2)))
            .ok_or_else(|| "timestamp rounding overflow".to_owned())?
    };
    let magnitude = i128::try_from(magnitude).map_err(|_| "timestamp is too large".to_owned())?;
    Ok(if negative { -magnitude } else { magnitude })
}

fn pow10(power: u32) -> Result<u128, String> {
    let mut value = 1u128;
    for _ in 0..power {
        value = value
            .checked_mul(10)
            .ok_or_else(|| "decimal scale is too large".to_owned())?;
    }
    Ok(value)
}

fn merge_and_normalize(
    mut host: Vec<TimedByte>,
    controller: Vec<TimedByte>,
    capture_end_ps: i128,
) -> Result<(Vec<NormalizedByte>, u64, i128), CliError> {
    let total = host
        .len()
        .checked_add(controller.len())
        .filter(|total| *total <= CAPTURE_ASSEMBLY_MAX_RAW_BYTES)
        .ok_or(CliError::TooManyBytes {
            maximum: CAPTURE_ASSEMBLY_MAX_RAW_BYTES,
        })?;
    host.reserve(controller.len());
    host.extend(controller);
    debug_assert_eq!(host.len(), total);
    host.sort_by_key(|record| record.completion_ps);
    for pair in host.windows(2) {
        if pair[0].completion_ps == pair[1].completion_ps {
            return Err(CliError::AmbiguousOrder {
                completion_ps: pair[0].completion_ps,
                first_row: pair[0].source_row,
                second_row: pair[1].source_row,
            });
        }
    }
    let origin_ps = host
        .first()
        .expect("both nonempty directions checked by parser")
        .completion_ps;
    let last_byte_ps = host.last().expect("nonempty merged bytes").completion_ps;
    if capture_end_ps < last_byte_ps {
        return Err(CliError::CaptureEndBeforeLastByte {
            capture_end_ps,
            last_byte_ps,
        });
    }
    let ended_us = rounded_nonnegative_us(capture_end_ps - origin_ps)?;
    let records = host
        .into_iter()
        .map(|record| {
            Ok(NormalizedByte {
                elapsed_us: rounded_nonnegative_us(record.completion_ps - origin_ps)?,
                direction: record.direction,
                byte: record.byte,
            })
        })
        .collect::<Result<Vec<_>, CliError>>()?;
    Ok((records, ended_us, origin_ps))
}

fn rounded_nonnegative_us(picoseconds: i128) -> Result<u64, CliError> {
    if picoseconds < 0 {
        return Err(CliError::TimeRange);
    }
    let rounded = picoseconds
        .checked_add(PICOSECONDS_PER_MICROSECOND / 2)
        .ok_or(CliError::TimeRange)?
        / PICOSECONDS_PER_MICROSECOND;
    u64::try_from(rounded).map_err(|_| CliError::TimeRange)
}

fn require_extension(
    path: &Path,
    extension: &'static str,
    role: &'static str,
) -> Result<(), CliError> {
    let matches = path
        .extension()
        .and_then(OsStr::to_str)
        .is_some_and(|observed| observed.eq_ignore_ascii_case(extension));
    if !matches {
        return Err(CliError::Extension {
            role,
            extension,
            path: path.to_path_buf(),
        });
    }
    Ok(())
}

fn reject_symlink_or_nonregular(path: &Path, role: &'static str) -> Result<u64, CliError> {
    reject_windows_device_path(path, role)?;
    let metadata = fs::symlink_metadata(path).map_err(|source| CliError::Io {
        operation: "inspect",
        path: path.to_path_buf(),
        source,
    })?;
    if metadata.file_type().is_symlink() {
        return Err(CliError::Symlink {
            role,
            path: path.to_path_buf(),
        });
    }
    if !metadata.file_type().is_file() {
        return Err(CliError::NotRegularFile {
            role,
            path: path.to_path_buf(),
        });
    }
    Ok(metadata.len())
}

fn read_bounded_regular_file(
    path: &Path,
    role: &'static str,
    maximum: usize,
) -> Result<(Vec<u8>, String), CliError> {
    let observed = reject_symlink_or_nonregular(path, role)?;
    if observed > maximum as u64 {
        return Err(CliError::FileTooLong {
            role,
            observed,
            maximum,
        });
    }
    let mut file = File::open(path).map_err(|source| CliError::Io {
        operation: "open",
        path: path.to_path_buf(),
        source,
    })?;
    let mut bytes = Vec::with_capacity(observed as usize);
    file.read_to_end(&mut bytes)
        .map_err(|source| CliError::Io {
            operation: "read",
            path: path.to_path_buf(),
            source,
        })?;
    if bytes.len() > maximum {
        return Err(CliError::FileTooLong {
            role,
            observed: bytes.len() as u64,
            maximum,
        });
    }
    let digest = sha256_bytes(&bytes);
    Ok((bytes, digest))
}

fn hash_regular_file(path: &Path, role: &'static str) -> Result<String, CliError> {
    reject_symlink_or_nonregular(path, role)?;
    let mut file = File::open(path).map_err(|source| CliError::Io {
        operation: "open",
        path: path.to_path_buf(),
        source,
    })?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0; SOURCE_HASH_BUFFER_LEN];
    loop {
        let read = file.read(&mut buffer).map_err(|source| CliError::Io {
            operation: "read",
            path: path.to_path_buf(),
            source,
        })?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(hex(&hasher.finalize()))
}

fn validate_saleae_archive(path: &Path) -> Result<(), CliError> {
    reject_symlink_or_nonregular(path, "source capture")?;
    let mut file = File::open(path).map_err(|source| CliError::Io {
        operation: "open",
        path: path.to_path_buf(),
        source,
    })?;
    let mut magic = [0u8; 4];
    file.read_exact(&mut magic)
        .map_err(|_| CliError::BadSaleaeArchive(path.to_path_buf()))?;
    if magic != *b"PK\x03\x04" {
        return Err(CliError::BadSaleaeArchive(path.to_path_buf()));
    }
    Ok(())
}

fn prepare_output(path: &Path) -> Result<(), CliError> {
    reject_windows_device_path(path, "output")?;
    if fs::symlink_metadata(path).is_ok() {
        return Err(CliError::OutputExists(path.to_path_buf()));
    }
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let metadata = fs::metadata(parent).map_err(|source| CliError::Io {
        operation: "inspect output parent",
        path: parent.to_path_buf(),
        source,
    })?;
    if !metadata.is_dir() {
        return Err(CliError::OutputParentNotDirectory(parent.to_path_buf()));
    }
    Ok(())
}

fn reject_windows_device_path(path: &Path, role: &'static str) -> Result<(), CliError> {
    let display = path.to_string_lossy();
    let normalized = display.replace('/', "\\");
    if normalized.starts_with("\\\\.\\")
        || normalized.starts_with("\\\\?\\")
        || normalized.starts_with("\\??\\")
    {
        return Err(CliError::UnsafePath {
            role,
            path: path.to_path_buf(),
        });
    }
    for component in path.components() {
        let Some(component) = component.as_os_str().to_str() else {
            continue;
        };
        let trimmed = component.trim_end_matches([' ', '.']);
        let stem = trimmed
            .split('.')
            .next()
            .unwrap_or_default()
            .to_ascii_uppercase();
        let reserved = matches!(stem.as_str(), "CON" | "PRN" | "AUX" | "NUL" | "CLOCK$")
            || stem.strip_prefix("COM").is_some_and(|number| {
                matches!(number, "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9")
            })
            || stem.strip_prefix("LPT").is_some_and(|number| {
                matches!(number, "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9")
            });
        if reserved {
            return Err(CliError::UnsafePath {
                role,
                path: path.to_path_buf(),
            });
        }
    }
    Ok(())
}

fn write_create_new(path: &Path, bytes: &[u8]) -> Result<(), CliError> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|source| {
            if source.kind() == io::ErrorKind::AlreadyExists {
                CliError::OutputExists(path.to_path_buf())
            } else {
                CliError::Io {
                    operation: "create output",
                    path: path.to_path_buf(),
                    source,
                }
            }
        })?;
    file.write_all(bytes).map_err(|source| CliError::Io {
        operation: "write output",
        path: path.to_path_buf(),
        source,
    })?;
    file.sync_all().map_err(|source| CliError::Io {
        operation: "sync output",
        path: path.to_path_buf(),
        source,
    })?;
    Ok(())
}

fn sha256_bytes(bytes: &[u8]) -> String {
    hex(&Sha256::digest(bytes))
}

fn hex(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(&mut output, "{byte:02x}").expect("writing to String cannot fail");
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use dcent_avalon_proto::nano3_uart::{
        crc16_xmodem, STOCK_POLL_ATTEMPT_LIMIT, STOCK_POLL_RESPONSE_TIMEOUT_MS,
    };
    use dcent_avalon_proto::nano3_uart_transcript::{
        encode_capture_artifact, CaptureEvent, CaptureWindow,
    };
    use std::sync::atomic::{AtomicU64, Ordering};

    const FRAME: [u8; 12] = [
        0x43, 0x4e, 0x75, 0x83, 0x13, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
    ];

    static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

    struct TestDir(PathBuf);

    impl TestDir {
        fn new() -> Self {
            let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
            let path = env::temp_dir().join(format!(
                "dcent-nano3-n3cap-test-{}-{sequence}",
                std::process::id()
            ));
            fs::create_dir(&path).unwrap();
            Self(path)
        }

        fn join(&self, name: &str) -> PathBuf {
            self.0.join(name)
        }
    }

    impl Drop for TestDir {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.0).unwrap();
        }
    }

    fn csv_for(frame: &[u8], start_us: u64) -> String {
        let mut csv = String::from("Time [s],Data\n");
        for (index, byte) in frame.iter().enumerate() {
            let time_us = start_us + index as u64 * 100;
            writeln!(&mut csv, "0.{time_us:06},0x{byte:02x}").unwrap();
        }
        csv
    }

    fn native_frame(packet_type: u8, payload: &[u8]) -> Vec<u8> {
        let mut bytes = vec![0x43, 0x4e, 0, 0, packet_type, 0, 0, 0, 1, 0];
        bytes.extend_from_slice(&(payload.len() as u16).to_le_bytes());
        bytes.extend_from_slice(payload);
        let crc = crc16_xmodem(&bytes[4..]);
        bytes[2..4].copy_from_slice(&crc.to_le_bytes());
        bytes
    }

    fn init_artifact(include_trailing_poll: bool) -> Vec<u8> {
        let detect = native_frame(0x10, &[0; 4]);
        let mut detect_ack_payload = vec![0xa5; 69];
        detect_ack_payload[4..20]
            .copy_from_slice(&core::array::from_fn::<_, 16, _>(|index| index as u8));
        detect_ack_payload.extend_from_slice(b"model\0firmware\0");
        detect_ack_payload.push(4);
        let detect_ack = native_frame(0x11, &detect_ack_payload);
        let mut sync_payload = core::array::from_fn::<_, 17, _>(|index| index as u8);
        sync_payload[16] = 1;
        let sync = native_frame(0x12, &sync_payload);
        let sync_ack = native_frame(0x13, &[]);
        let work_level = native_frame(0x41, &2u32.to_le_bytes());
        let finish = native_frame(0x31, &[]);
        let poll = native_frame(0x33, &[0; 4]);
        let frames = [
            &detect,
            &detect,
            &detect_ack,
            &sync,
            &sync_ack,
            &work_level,
            &finish,
            &poll,
        ];
        let directions = [
            CaptureDirection::HostToController,
            CaptureDirection::HostToController,
            CaptureDirection::ControllerToHost,
            CaptureDirection::HostToController,
            CaptureDirection::ControllerToHost,
            CaptureDirection::HostToController,
            CaptureDirection::HostToController,
            CaptureDirection::HostToController,
        ];
        let times = [
            0, 200_000, 200_050, 200_100, 200_150, 200_200, 200_250, 200_300,
        ];
        let count = if include_trailing_poll { 8 } else { 7 };
        let events: Vec<_> = (0..count)
            .map(|index| CaptureEvent {
                elapsed_us: times[index],
                direction: directions[index],
                bytes: frames[index],
            })
            .collect();
        encode_capture_artifact(CaptureWindow::new(&events, 200_350)).unwrap()
    }

    fn exhausted_poll_artifact(final_timeout_complete: bool) -> Vec<u8> {
        let poll = native_frame(0x33, &[0; 4]);
        let timeout_us = u64::from(STOCK_POLL_RESPONSE_TIMEOUT_MS) * 1_000;
        let events: Vec<_> = (0..STOCK_POLL_ATTEMPT_LIMIT)
            .map(|attempt| CaptureEvent {
                elapsed_us: u64::from(attempt) * timeout_us,
                direction: CaptureDirection::HostToController,
                bytes: &poll,
            })
            .collect();
        let ended_us =
            u64::from(STOCK_POLL_ATTEMPT_LIMIT) * timeout_us - u64::from(!final_timeout_complete);
        encode_capture_artifact(CaptureWindow::new(&events, ended_us)).unwrap()
    }

    fn response_poll_artifact() -> Vec<u8> {
        let poll = native_frame(0x33, &[0; 4]);
        let response = native_frame(0x52, &[0xaa]);
        let events = [
            CaptureEvent {
                elapsed_us: 0,
                direction: CaptureDirection::HostToController,
                bytes: &poll,
            },
            CaptureEvent {
                elapsed_us: 1_000,
                direction: CaptureDirection::ControllerToHost,
                bytes: &response,
            },
        ];
        encode_capture_artifact(CaptureWindow::new(&events, 1_100)).unwrap()
    }

    fn observed_stateful_poll_artifact() -> Vec<u8> {
        let poll = native_frame(0x33, &[0, 0, 0, 1]);
        let mut status = [0u8; 52];
        status[0] = 4;
        let response = native_frame(0x51, &status);
        let events = [
            CaptureEvent {
                elapsed_us: 0,
                direction: CaptureDirection::HostToController,
                bytes: &poll,
            },
            CaptureEvent {
                elapsed_us: 1_000,
                direction: CaptureDirection::ControllerToHost,
                bytes: &response,
            },
        ];
        encode_capture_artifact(CaptureWindow::new(&events, 1_100)).unwrap()
    }

    fn combined_init_poll_artifact() -> Vec<u8> {
        let init_bytes = init_artifact(false);
        let poll_bytes = exhausted_poll_artifact(true);
        let init = decode_capture_artifact(&init_bytes).unwrap();
        let poll = decode_capture_artifact(&poll_bytes).unwrap();
        let poll_offset_us = 400_000;
        let mut events = init.events().to_vec();
        events.extend(poll.events().iter().map(|event| CaptureEvent {
            elapsed_us: event.elapsed_us + poll_offset_us,
            direction: event.direction,
            bytes: event.bytes,
        }));
        encode_capture_artifact(CaptureWindow::new(
            &events,
            poll.ended_us() + poll_offset_us,
        ))
        .unwrap()
    }

    #[test]
    fn decimal_seconds_parser_is_signed_scientific_and_picosecond_deterministic() {
        assert_eq!(parse_seconds_to_ps("0").unwrap(), 0);
        assert_eq!(parse_seconds_to_ps("1.25").unwrap(), 1_250_000_000_000);
        assert_eq!(parse_seconds_to_ps("-2.5e-6").unwrap(), -2_500_000);
        assert_eq!(parse_seconds_to_ps("5e-13").unwrap(), 1);
        assert_eq!(parse_seconds_to_ps("4e-13").unwrap(), 0);
    }

    #[test]
    fn decimal_seconds_parser_rejects_nondecimal_and_unbounded_scales() {
        for invalid in ["", ".", "NaN", "1.2.3", "1e2e3", "1e99"] {
            assert!(parse_seconds_to_ps(invalid).is_err(), "{invalid}");
        }
    }

    #[test]
    fn byte_parser_requires_the_explicit_cli_radix() {
        assert_eq!(parse_byte("0x43", DataRadix::Hex), Some(0x43));
        assert_eq!(parse_byte("43", DataRadix::Hex), Some(0x43));
        assert_eq!(parse_byte("255", DataRadix::Decimal), Some(255));
        assert_eq!(parse_byte("ff", DataRadix::Decimal), None);
        assert_eq!(parse_byte("256", DataRadix::Decimal), None);
        assert_eq!(parse_byte("123", DataRadix::Hex), None);
    }

    #[test]
    fn csv_parser_uses_byte_completion_time_and_fixed_direction() {
        let decoded = parse_saleae_csv(
            Cursor::new("Time [s],Data\n-0.000100,0x43\n0.000000,0x4e\n"),
            Path::new("host.csv"),
            "host-to-controller",
            CaptureDirection::HostToController,
            TimeSemantics::Start,
            DataRadix::Hex,
        )
        .unwrap();
        assert_eq!(
            decoded[0].completion_ps,
            -100_000_000 + UART_BYTE_DURATION_PS
        );
        assert_eq!(decoded[1].completion_ps, UART_BYTE_DURATION_PS);
        assert!(decoded
            .iter()
            .all(|byte| byte.direction == CaptureDirection::HostToController));
    }

    #[test]
    fn csv_parser_accepts_end_time_and_decimal_data() {
        let decoded = parse_saleae_csv(
            Cursor::new("End Time [s],Value\n0.1,67\n0.2,78\n"),
            Path::new("controller.csv"),
            "controller-to-host",
            CaptureDirection::ControllerToHost,
            TimeSemantics::End,
            DataRadix::Decimal,
        )
        .unwrap();
        assert_eq!(decoded[0].completion_ps, 100_000_000_000);
        assert_eq!(decoded[0].byte, 0x43);
        assert_eq!(decoded[1].byte, 0x4e);
    }

    #[test]
    fn csv_parser_rejects_header_time_and_data_drift() {
        let missing = parse_saleae_csv(
            Cursor::new("When,Payload\n0,0x43\n"),
            Path::new("host.csv"),
            "host-to-controller",
            CaptureDirection::HostToController,
            TimeSemantics::Start,
            DataRadix::Hex,
        );
        assert!(matches!(missing, Err(CliError::MissingColumn { .. })));

        let backward = parse_saleae_csv(
            Cursor::new("Time [s],Data\n0.2,0x43\n0.1,0x4e\n"),
            Path::new("host.csv"),
            "host-to-controller",
            CaptureDirection::HostToController,
            TimeSemantics::End,
            DataRadix::Hex,
        );
        assert!(matches!(
            backward,
            Err(CliError::NonIncreasingTime { row: 3, .. })
        ));
    }

    #[test]
    fn merge_normalizes_negative_saleae_time_and_preserves_precise_order() {
        let host = vec![TimedByte {
            completion_ps: -10,
            direction: CaptureDirection::HostToController,
            byte: 0x43,
            source_row: 2,
        }];
        let controller = vec![TimedByte {
            completion_ps: 10,
            direction: CaptureDirection::ControllerToHost,
            byte: 0x4e,
            source_row: 2,
        }];
        let (records, ended_us, origin_ps) =
            merge_and_normalize(host, controller, 2_000_000).unwrap();
        assert_eq!(origin_ps, -10);
        assert_eq!(records[0].elapsed_us, 0);
        assert_eq!(records[1].elapsed_us, 0);
        assert_eq!(records[0].direction, CaptureDirection::HostToController);
        assert_eq!(records[1].direction, CaptureDirection::ControllerToHost);
        assert_eq!(ended_us, 2);
    }

    #[test]
    fn merge_rejects_cross_direction_ties_and_early_end() {
        let host = vec![TimedByte {
            completion_ps: 1,
            direction: CaptureDirection::HostToController,
            byte: 0,
            source_row: 2,
        }];
        let tied = vec![TimedByte {
            completion_ps: 1,
            direction: CaptureDirection::ControllerToHost,
            byte: 0,
            source_row: 2,
        }];
        assert!(matches!(
            merge_and_normalize(host.clone(), tied, 2),
            Err(CliError::AmbiguousOrder { .. })
        ));
        let later = vec![TimedByte {
            completion_ps: 2,
            direction: CaptureDirection::ControllerToHost,
            byte: 0,
            source_row: 2,
        }];
        assert!(matches!(
            merge_and_normalize(host, later, 1),
            Err(CliError::CaptureEndBeforeLastByte { .. })
        ));
    }

    #[test]
    fn parsed_bidirectional_exports_assemble_and_decode_canonically() {
        let host_csv = csv_for(&FRAME, 0);
        let controller_csv = csv_for(&FRAME, 50);
        let host = parse_saleae_csv(
            Cursor::new(host_csv),
            Path::new("host.csv"),
            "host-to-controller",
            CaptureDirection::HostToController,
            TimeSemantics::End,
            DataRadix::Hex,
        )
        .unwrap();
        let controller = parse_saleae_csv(
            Cursor::new(controller_csv),
            Path::new("controller.csv"),
            "controller-to-host",
            CaptureDirection::ControllerToHost,
            TimeSemantics::End,
            DataRadix::Hex,
        )
        .unwrap();
        let (records, ended_us, _) = merge_and_normalize(host, controller, 2_000_000_000).unwrap();
        let chunks: Vec<_> = records
            .iter()
            .map(|record| CaptureByteChunk {
                elapsed_us: record.elapsed_us,
                direction: record.direction,
                bytes: std::slice::from_ref(&record.byte),
            })
            .collect();
        let artifact = assemble_capture_artifact(&chunks, ended_us).unwrap();
        let decoded = decode_capture_artifact(&artifact).unwrap();
        assert_eq!(decoded.events().len(), 2);
        assert_eq!(
            decoded.events()[0].direction,
            CaptureDirection::HostToController
        );
        assert_eq!(
            decoded.events()[1].direction,
            CaptureDirection::ControllerToHost
        );
        assert_eq!(decoded.events()[0].bytes, FRAME);
        assert_eq!(decoded.events()[1].bytes, FRAME);
    }

    #[test]
    fn command_parser_requires_every_explicit_capture_semantic() {
        let command = parse_command(
            [
                "assemble-saleae",
                "--source-capture",
                "capture.sal",
                "--host-to-controller",
                "host.csv",
                "--controller-to-host",
                "controller.csv",
                "--capture-end-s",
                "1.0",
                "--time-semantics",
                "start",
                "--data-radix",
                "hex",
                "--output",
                "capture.n3cap",
            ]
            .into_iter()
            .map(str::to_owned),
        )
        .unwrap();
        assert!(matches!(command, Command::Assemble(_)));

        let missing = parse_command(
            ["verify", "--unknown", "capture.n3cap"]
                .into_iter()
                .map(str::to_owned),
        );
        assert!(matches!(missing, Err(CliError::Usage(_))));

        assert!(matches!(
            parse_command(
                [
                    "validate-init",
                    "--input",
                    "init.n3cap",
                    "--requested-work-level",
                    "2",
                ]
                .into_iter()
                .map(str::to_owned),
            )
            .unwrap(),
            Command::ValidateInit {
                requested_work_level: 2,
                ..
            }
        ));
        assert!(matches!(
            parse_command(
                ["validate-poll", "--input", "poll.n3cap"]
                    .into_iter()
                    .map(str::to_owned),
            )
            .unwrap(),
            Command::ValidatePoll { .. }
        ));
        assert!(matches!(
            parse_command(
                ["inventory", "--input", "capture.n3cap"]
                    .into_iter()
                    .map(str::to_owned),
            )
            .unwrap(),
            Command::Inventory { .. }
        ));
        assert_eq!(
            parse_command(
                [
                    "extract",
                    "--input",
                    "capture.n3cap",
                    "--first-event",
                    "0",
                    "--event-count",
                    "7",
                    "--output",
                    "init.n3cap",
                ]
                .into_iter()
                .map(str::to_owned),
            )
            .unwrap(),
            Command::Extract {
                input: PathBuf::from("capture.n3cap"),
                first_event: 0,
                event_count: 7,
                output: PathBuf::from("init.n3cap"),
            }
        );
        assert!(matches!(
            parse_command(
                [
                    "validate-init",
                    "--input",
                    "init.n3cap",
                    "--requested-work-level",
                    "256",
                ]
                .into_iter()
                .map(str::to_owned),
            ),
            Err(CliError::Usage(_))
        ));
        for invalid in ["01", "+1", "-1", "1.0"] {
            assert!(matches!(
                parse_command(
                    [
                        "extract",
                        "--input",
                        "capture.n3cap",
                        "--first-event",
                        invalid,
                        "--event-count",
                        "1",
                        "--output",
                        "event.n3cap",
                    ]
                    .into_iter()
                    .map(str::to_owned),
                ),
                Err(CliError::Usage(_))
            ));
        }
    }

    #[test]
    fn extension_gate_is_case_insensitive_but_role_specific() {
        assert!(require_extension(Path::new("capture.SAL"), "sal", "source").is_ok());
        assert!(matches!(
            require_extension(Path::new("capture.bin"), "sal", "source"),
            Err(CliError::Extension { .. })
        ));
    }

    #[test]
    fn every_file_role_rejects_windows_device_names_even_with_an_extension() {
        for unsafe_path in ["NUL.n3cap", "com3.N3CAP", r"\\.\pipe\capture.n3cap"] {
            assert!(matches!(
                reject_windows_device_path(Path::new(unsafe_path), "test input"),
                Err(CliError::UnsafePath {
                    role: "test input",
                    ..
                })
            ));
        }
        assert!(reject_windows_device_path(Path::new("capture.n3cap"), "output").is_ok());
    }

    #[test]
    fn file_only_cli_round_trip_is_create_new_and_self_verifying() {
        let directory = TestDir::new();
        let source_capture = directory.join("capture.sal");
        let host_csv = directory.join("host.csv");
        let controller_csv = directory.join("controller.csv");
        let output = directory.join("capture.n3cap");
        fs::write(&source_capture, b"PK\x03\x04offline-source-fixture").unwrap();
        fs::write(&host_csv, csv_for(&FRAME, 0)).unwrap();
        fs::write(&controller_csv, csv_for(&FRAME, 50)).unwrap();
        let args = AssembleArgs {
            source_capture,
            host_csv,
            controller_csv,
            capture_end_s: "0.002".into(),
            time_semantics: TimeSemantics::End,
            data_radix: DataRadix::Hex,
            output: output.clone(),
        };

        run_assemble(&args).unwrap();
        run_verify(&output).unwrap();
        assert!(matches!(
            run_assemble(&args),
            Err(CliError::OutputExists(path)) if path == output
        ));
        let (artifact, _) =
            read_bounded_regular_file(&output, "test artifact", CAPTURE_ARTIFACT_MAX_LEN).unwrap();
        let decoded = decode_capture_artifact(&artifact).unwrap();
        assert_eq!(decoded.events().len(), 2);
        assert_eq!(
            sha256_bytes(&artifact),
            "75d549cc0e1d42e71caf2542ace336de12b0c89566e448c0b2b82af922344761"
        );
        assert_eq!(
            hex(decoded.digest()),
            "4294bb1b9c7a9e983fb336a784200c7f840d2414183cf07534567a69812b05a3"
        );
    }

    #[test]
    fn inventory_is_indexed_bounded_and_payload_free() {
        let artifact = response_poll_artifact();
        let decoded = decode_capture_artifact(&artifact).unwrap();
        let report = inventory_report(&decoded, &sha256_bytes(&artifact));
        assert!(report.contains("events=2\n"));
        assert!(
            report.contains("event[0]=elapsed_us:0 direction:host-to-controller packet_type:0x33")
        );
        assert!(report
            .contains("event[1]=elapsed_us:1000 direction:controller-to-host packet_type:0x52"));
        assert!(report.contains("payload_len:1 frame_len:13 frame_sha256:"));
        assert!(!report.contains("payload:"));
        assert!(report.ends_with("authorizes_transmit=false\nauthorizes_device=false\n"));
    }

    #[test]
    fn extract_cli_produces_semantic_init_and_poll_artifacts_without_overwrite() {
        let directory = TestDir::new();
        let source_path = directory.join("session.n3cap");
        let init_path = directory.join("init.n3cap");
        let poll_path = directory.join("poll.n3cap");
        let source_bytes = combined_init_poll_artifact();
        assert_eq!(
            sha256_bytes(&source_bytes),
            "405737dea8a48ac851d3f61a468a501b4d2fb33e010e2421d5cd0e1da59d4a17"
        );
        assert_eq!(
            hex(decode_capture_artifact(&source_bytes).unwrap().digest()),
            "9ca1c5a160051ba6486de691c5f1687d3f1e28dfd3a819be0c980bc8f4fa9f7d"
        );
        fs::write(&source_path, source_bytes).unwrap();

        run_inventory(&source_path).unwrap();
        run_extract(&source_path, 0, 7, &init_path).unwrap();
        run_extract(&source_path, 7, 5, &poll_path).unwrap();
        run_validate_init(&init_path, 2).unwrap();
        run_validate_poll(&poll_path).unwrap();

        let (init_bytes, _) =
            read_bounded_regular_file(&init_path, "init", CAPTURE_ARTIFACT_MAX_LEN).unwrap();
        let init = decode_capture_artifact(&init_bytes).unwrap();
        assert_eq!(init.events().len(), 7);
        assert_eq!(init.ended_us(), 200_250);
        assert_eq!(
            sha256_bytes(&init_bytes),
            "40e1e6018f92a72e696fab054b280326e91bcf9fb9b88c9e27c3e8eb76db4b09"
        );
        assert_eq!(
            hex(init.digest()),
            "02c8e0439c24cbfc022cc8dd46ad6bd1635f61e7241c75973cfba8bf3cc64223"
        );

        let (poll_bytes, _) =
            read_bounded_regular_file(&poll_path, "poll", CAPTURE_ARTIFACT_MAX_LEN).unwrap();
        let poll = decode_capture_artifact(&poll_bytes).unwrap();
        assert_eq!(poll.events().len(), 5);
        assert_eq!(poll.ended_us(), 1_400_000);
        assert_eq!(
            sha256_bytes(&poll_bytes),
            "eb813c1e6ba0d029cb6eb41fc412628dff00c08b57345592c08ebeb5cec716b1"
        );
        assert_eq!(
            hex(poll.digest()),
            "a6e761e7e83c11ba24cb20313aa0ea592798b9abef7ba43a88145d21cced60d0"
        );

        assert!(matches!(
            run_extract(&source_path, 0, 7, &init_path),
            Err(CliError::OutputExists(path)) if path == init_path
        ));
    }

    #[test]
    fn semantic_cli_validates_exact_init_and_complete_poll_exhaustion() {
        let directory = TestDir::new();
        let init_path = directory.join("init.n3cap");
        let poll_path = directory.join("poll.n3cap");
        let response_poll_path = directory.join("response-poll.n3cap");
        let stateful_poll_path = directory.join("stateful-poll.n3cap");
        let init = init_artifact(false);
        let poll = exhausted_poll_artifact(true);
        assert_eq!(
            sha256_bytes(&init),
            "760cb6ee7b4fc0cf46fb3f850252deb7b2285d06bb4a4b0277bcd3b6301d4c96"
        );
        assert_eq!(
            hex(decode_capture_artifact(&init).unwrap().digest()),
            "7ac3d6b09b11e2b454d5876c876ddb018bda75a6cbc30e7339c19134b28ebd63"
        );
        assert_eq!(
            sha256_bytes(&poll),
            "ae4fbca3d62a9d23fcaf6f083a78bbba3ae7e1843619e700888a55efd6af1cd9"
        );
        assert_eq!(
            hex(decode_capture_artifact(&poll).unwrap().digest()),
            "5a7bfcc2059f9c3b7a7f2dcdfcc3eda47cd97f24803854c1ac898b4d8240c6f2"
        );
        fs::write(&init_path, init).unwrap();
        fs::write(&poll_path, poll).unwrap();
        fs::write(&response_poll_path, response_poll_artifact()).unwrap();
        fs::write(&stateful_poll_path, observed_stateful_poll_artifact()).unwrap();

        run_validate_init(&init_path, 2).unwrap();
        run_validate_poll(&poll_path).unwrap();
        run_validate_poll(&response_poll_path).unwrap();
        run_validate_poll(&stateful_poll_path).unwrap();
    }

    #[test]
    fn semantic_cli_rejects_trailing_init_and_incomplete_poll_timeout() {
        let directory = TestDir::new();
        let init_path = directory.join("init.n3cap");
        let poll_path = directory.join("poll.n3cap");
        fs::write(&init_path, init_artifact(true)).unwrap();
        fs::write(&poll_path, exhausted_poll_artifact(false)).unwrap();

        assert!(matches!(
            run_validate_init(&init_path, 2),
            Err(CliError::Transcript(
                Nano3TranscriptError::TrailingEvents { .. }
            ))
        ));
        assert!(matches!(
            run_validate_poll(&poll_path),
            Err(CliError::Transcript(
                Nano3TranscriptError::CaptureEndedBeforeTimeout { .. }
            ))
        ));
    }
}
