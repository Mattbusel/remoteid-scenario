//! Spec-compliant Remote ID test vectors for counter-UAS detectors.
//!
//! `remoteid-scenario` is a bench harness. It builds synthetic Remote ID
//! message streams in memory with the encoders in [`remoteid`] 0.3.3 and
//! writes them to a file or stdout, as RIDF, pcap or JSON lines, so an
//! engineer can pipe a flood, a spoof or a clean baseline into detection
//! software and prove the detector reacts the way it should. It is to a
//! counter-UAS detector what a fuzzer corpus or an EICAR test file is to the
//! software it exercises.
//!
//! # Hard boundaries
//!
//! This crate is data only.
//!
//! * No radio. It never opens an SDR, a Bluetooth or Wi-Fi adapter, or any
//!   device.
//! * No transmit path. It never broadcasts. Every byte goes to a file or a
//!   pipe for a software detector to read.
//! * No BLE / Wi-Fi / SDR / HackRF / ESP32 / nRF support, and no firmware
//!   flashing.
//! * No instructions for broadcasting into real airspace, and no evasion
//!   guidance.
//!
//! The frames it produces are exactly what [`remoteid`] would encode for a
//! firmware transmitter, aimed at a file instead of a transmitter. Nothing
//! on the RF side is new here. If a change would add a transmit or broadcast
//! capability, it does not belong in this crate.
//!
//! # Example
//!
//! ```
//! use remoteid_scenario::{generate, Scenario, ScenarioKind, ScenarioWriter};
//!
//! let scenario = Scenario::new(ScenarioKind::Flood, 50);
//! let frames = generate(&scenario);
//! let mut ridf = Vec::new();
//! ScenarioWriter::new(frames).to_ridf(&mut ridf).unwrap();
//! assert!(ridf.starts_with(b"RIDF"));
//! ```

pub mod config;
pub mod generate;
pub mod writer;

pub use config::{
    AddressMode, CounterMode, GenuineTrack, OperatorPosition, Scenario, ScenarioKind,
    SerialTemplate, SourceModel, Timing,
};
pub use generate::{generate, EmittedFrame};
pub use writer::{Format, JsonlRecord, ScenarioWriter};
