//! Command-line front end for the test-vector generator.
//!
//! It builds one scenario and writes it to a file or stdout. It opens no
//! radio and transmits nothing; the output is data for a software detector
//! under test.

use std::fs::File;
use std::io::{self, BufWriter, Write};
use std::process::ExitCode;

use remoteid_scenario::{generate, Format, Scenario, ScenarioKind, ScenarioWriter};

fn usage() -> String {
    let scenarios = "flood | spoof | clean | count_spike | colocated";
    format!(
        "remoteid-scenario: Remote ID test-vector generator for counter-UAS detectors.\n\
         DATA ONLY. No radio, no transmit path. Output is for a software detector under test.\n\n\
         USAGE:\n  \
           remoteid-scenario <scenario> [--count N] [--format ridf|pcap|jsonl] [--out PATH]\n\n\
         SCENARIOS:\n  {scenarios}\n\n\
         OPTIONS:\n  \
           --count N        number of fake units (or honest drones for `clean`)  [default 50]\n  \
           --format FMT     ridf (default), pcap, or jsonl\n  \
           --out PATH       output file; omit or use - for stdout\n  \
           --fps N          frames per second per unit  [default 2]\n  \
           --window N       window length in seconds  [default 10]\n  \
           -h, --help       this help"
    )
}

struct Args {
    kind: ScenarioKind,
    count: u32,
    format: Format,
    out: Option<String>,
    fps: Option<u32>,
    window: Option<u32>,
}

fn parse(mut it: impl Iterator<Item = String>) -> Result<Args, String> {
    let kind_name = it.next().ok_or_else(usage)?;
    if kind_name == "-h" || kind_name == "--help" {
        return Err(usage());
    }
    let kind = ScenarioKind::from_name(&kind_name)
        .ok_or_else(|| format!("unknown scenario `{kind_name}`\n\n{}", usage()))?;
    let mut args = Args {
        kind,
        count: 50,
        format: Format::Ridf,
        out: None,
        fps: None,
        window: None,
    };
    while let Some(flag) = it.next() {
        match flag.as_str() {
            "--count" => {
                args.count = next_num(&mut it, "--count")?;
            }
            "--fps" => args.fps = Some(next_num(&mut it, "--fps")?),
            "--window" => args.window = Some(next_num(&mut it, "--window")?),
            "--format" => {
                let v = it.next().ok_or("--format needs a value")?;
                args.format =
                    Format::from_name(&v).ok_or_else(|| format!("unknown format `{v}`"))?;
            }
            "--out" => args.out = Some(it.next().ok_or("--out needs a value")?),
            "-h" | "--help" => return Err(usage()),
            other => return Err(format!("unknown option `{other}`\n\n{}", usage())),
        }
    }
    Ok(args)
}

fn next_num(it: &mut impl Iterator<Item = String>, name: &str) -> Result<u32, String> {
    let v = it.next().ok_or(format!("{name} needs a value"))?;
    v.parse::<u32>()
        .map_err(|_| format!("{name} expects a number, got `{v}`"))
}

fn run() -> Result<(), String> {
    let args = parse(std::env::args().skip(1))?;
    let mut scenario = Scenario::new(args.kind, args.count);
    if let Some(fps) = args.fps {
        scenario.timing.frames_per_s = fps.max(1);
    }
    if let Some(window) = args.window {
        scenario.timing.window_s = window.max(1);
    }
    let writer = ScenarioWriter::new(generate(&scenario));

    match args.out.as_deref() {
        None | Some("-") => {
            let stdout = io::stdout();
            let mut lock = stdout.lock();
            writer
                .write(args.format, &mut lock)
                .map_err(|e| e.to_string())?;
            lock.flush().map_err(|e| e.to_string())?;
        }
        Some(path) => {
            let file = File::create(path).map_err(|e| format!("cannot write {path}: {e}"))?;
            let mut buf = BufWriter::new(file);
            writer
                .write(args.format, &mut buf)
                .map_err(|e| e.to_string())?;
            buf.flush().map_err(|e| e.to_string())?;
            eprintln!(
                "wrote {} frames ({}) to {path}",
                writer.frames().len(),
                scenario.kind.name()
            );
        }
    }
    Ok(())
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(msg) => {
            eprintln!("{msg}");
            ExitCode::FAILURE
        }
    }
}
