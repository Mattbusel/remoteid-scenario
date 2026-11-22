//! Writers that serialise a generated frame stream to a sink.
//!
//! Every writer takes a `&mut impl Write` and emits data. None of them opens
//! a radio, a socket or a device. The bytes are test vectors for a software
//! detector to ingest from a file or a pipe. There is no transmit path here
//! and there is none anywhere else in this crate.

use std::io::{self, Write};

use remoteid::capture::{self, CapturedFrame};
use remoteid::replay;
use remoteid::wifi::BeaconInfo;
use serde::{Deserialize, Serialize};

use crate::generate::EmittedFrame;

/// One JSON-lines record: the decoded message plus the observation metadata.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct JsonlRecord {
    /// Capture time, microseconds from the stream start epoch.
    pub time_us: u64,
    /// Transmitter the frame is attributed to.
    pub transmitter: remoteid::Transmitter,
    /// Radio link name.
    pub transport: String,
    /// Message counter.
    pub counter: u8,
    /// Signal strength, dBm.
    pub rssi_dbm: i8,
    /// Modelled Wi-Fi TSF, when present.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub tsf: Option<u64>,
    /// The decoded Remote ID message.
    pub message: remoteid::Message,
}

impl JsonlRecord {
    fn from_frame(f: &EmittedFrame) -> JsonlRecord {
        JsonlRecord {
            time_us: f.time_us,
            transmitter: f.transmitter,
            transport: f.transport.name().to_string(),
            counter: f.counter,
            rssi_dbm: f.rssi_dbm,
            tsf: f.tsf,
            message: f.message.clone(),
        }
    }
}

fn beacon_for(frame: &EmittedFrame) -> Option<BeaconInfo> {
    let tsf = frame.tsf?;
    let source = replay::transmitter_address(&frame.transmitter).unwrap_or([0; 6]);
    Some(BeaconInfo {
        source,
        sequence: frame.counter as u16,
        tsf,
        interval_tu: 100,
        capability: 0,
        ssid: [0; 32],
        ssid_len: 0,
    })
}

/// Converts one emitted frame to the remoteid capture type, encoding the
/// decoded message to its 25 byte broadcast form with remoteid's own encoder.
fn to_captured(frame: &EmittedFrame) -> Result<CapturedFrame, remoteid::Error> {
    let payload = frame.message.encode()?.to_vec();
    Ok(CapturedFrame {
        time_us: frame.time_us,
        transmitter: frame.transmitter,
        transport: frame.transport,
        counter: Some(frame.counter),
        payload,
        beacon: beacon_for(frame),
        rssi_dbm: Some(frame.rssi_dbm),
        utc_clock: true,
    })
}

/// Serialises a generated frame stream to the chosen sink. Construct it from
/// a `Vec<EmittedFrame>` and call one of the `to_*` methods.
pub struct ScenarioWriter {
    frames: Vec<EmittedFrame>,
}

impl ScenarioWriter {
    /// Wraps a generated frame stream.
    pub fn new(frames: Vec<EmittedFrame>) -> ScenarioWriter {
        ScenarioWriter { frames }
    }

    /// The frames being written.
    pub fn frames(&self) -> &[EmittedFrame] {
        &self.frames
    }

    /// Writes the stream as a RIDF file (remoteid's native capture format),
    /// the format [`crate`]'s companion analyzer re-ingests directly.
    pub fn to_ridf(&self, out: &mut impl Write) -> io::Result<()> {
        let captured: Result<Vec<_>, _> = self.frames.iter().map(to_captured).collect();
        let captured = captured.map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        let bytes = capture::to_ridf(&captured)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        out.write_all(&bytes)
    }

    /// Writes the stream as a classic pcap of Bluetooth LE link-layer
    /// advertising packets (link type 251, `LINKTYPE_BLUETOOTH_LE_LL`). Each
    /// packet is a real ADV_NONCONN_IND carrying the Remote ID service data,
    /// so a pcap reader decodes it back to the same message. Wi-Fi beacon and
    /// radiotap framing are deferred (see the README).
    pub fn to_pcap(&self, out: &mut impl Write) -> io::Result<()> {
        let mut file = capture::pcap_header(251);
        for frame in &self.frames {
            let payload = frame
                .message
                .encode()
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
            let addr = replay::transmitter_address(&frame.transmitter).unwrap_or([0; 6]);
            let pkt = ble_ll_adv_packet(addr, frame.counter, &payload);
            capture::pcap_push(&mut file, frame.time_us, &pkt);
        }
        out.write_all(&file)
    }

    /// Writes the stream as JSON lines, one decoded message per line.
    pub fn to_jsonl(&self, out: &mut impl Write) -> io::Result<()> {
        for frame in &self.frames {
            let line = serde_json::to_string(&JsonlRecord::from_frame(frame))?;
            out.write_all(line.as_bytes())?;
            out.write_all(b"\n")?;
        }
        Ok(())
    }

    /// Writes JSON lines to stdout.
    pub fn to_stdout(&self) -> io::Result<()> {
        let stdout = io::stdout();
        let mut lock = stdout.lock();
        self.to_jsonl(&mut lock)
    }
}

/// Builds a Bluetooth LE link-layer ADV_NONCONN_IND packet carrying one
/// Remote ID message as service data (UUID 0xFFFA, application code 0x0D).
/// This is the exact advertising structure remoteid decodes; it is written
/// to a capture file, never to a radio.
fn ble_ll_adv_packet(address: [u8; 6], counter: u8, message: &[u8]) -> Vec<u8> {
    // AD structure: length, Service Data (0x16), UUID 0xFFFA little-endian,
    // application code, counter, then the 25 byte message.
    let ad_len = 1 + 2 + 1 + 1 + message.len();
    let mut adv = Vec::with_capacity(1 + ad_len);
    adv.push(ad_len as u8);
    adv.push(0x16);
    adv.push(0xFA);
    adv.push(0xFF);
    adv.push(0x0D);
    adv.push(counter);
    adv.extend_from_slice(message);

    // LL PDU: ADV_NONCONN_IND (type 2), length, AdvA (6), AdvData.
    let mut pkt = Vec::with_capacity(4 + 2 + 6 + adv.len());
    pkt.extend_from_slice(&[0xD6, 0xBE, 0x89, 0x8E]); // advertising access address
    pkt.push(0x02); // PDU type 2 in the low nibble
    pkt.push((6 + adv.len()) as u8);
    pkt.extend_from_slice(&address);
    pkt.extend_from_slice(&adv);
    pkt
}

/// Output format for the binary and for round-trip helpers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    /// RIDF, remoteid's native capture format.
    Ridf,
    /// Classic pcap of BLE advertising packets.
    Pcap,
    /// JSON lines.
    Jsonl,
}

impl Format {
    /// Parses a format name.
    pub fn from_name(s: &str) -> Option<Format> {
        Some(match s {
            "ridf" => Format::Ridf,
            "pcap" => Format::Pcap,
            "jsonl" | "json" => Format::Jsonl,
            _ => return None,
        })
    }
}

impl ScenarioWriter {
    /// Writes the stream in `format` to `out`.
    pub fn write(&self, format: Format, out: &mut impl Write) -> io::Result<()> {
        match format {
            Format::Ridf => self.to_ridf(out),
            Format::Pcap => self.to_pcap(out),
            Format::Jsonl => self.to_jsonl(out),
        }
    }
}
