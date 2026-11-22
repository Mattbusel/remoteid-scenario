//! The generated streams must be spec-compliant: every frame has to decode
//! back through remoteid's own decoders to the message that was generated.

use remoteid::capture;
use remoteid::{IdType, Message};
use remoteid_scenario::writer::JsonlRecord;
use remoteid_scenario::{generate, Scenario, ScenarioKind, ScenarioWriter};

/// The serial of the genuine track, as the generator sanitises it.
const GENUINE_SERIAL: &str = "1581CREAL7A4F2C91";

fn basic_id_serials(messages: &[Message]) -> Vec<String> {
    messages
        .iter()
        .filter_map(|m| match m {
            Message::BasicId(b) if b.id_type == IdType::SerialNumber => {
                b.uas_id_str().map(|s| s.to_string())
            }
            _ => None,
        })
        .collect()
}

#[test]
fn flood_has_templated_fakes_and_exactly_one_genuine_track() {
    let fake_count = 40u32;
    let scenario = Scenario::new(ScenarioKind::Flood, fake_count);
    let frames = generate(&scenario);

    // Collect the distinct Basic ID serials.
    let messages: Vec<Message> = frames.iter().map(|f| f.message.clone()).collect();
    let mut serials: Vec<String> = basic_id_serials(&messages);
    serials.sort();
    serials.dedup();

    // The templated fakes all share the FAKE prefix; exactly one track is the
    // genuine one with its own serial.
    let fakes: Vec<&String> = serials.iter().filter(|s| s.contains("FAKE")).collect();
    let genuine: Vec<&String> = serials.iter().filter(|s| s.contains("REAL")).collect();

    assert_eq!(
        fakes.len() as u32,
        fake_count,
        "expected {fake_count} distinct templated fakes, got {}",
        fakes.len()
    );
    assert_eq!(
        genuine.len(),
        1,
        "expected exactly one genuine track, got {genuine:?}"
    );
    assert_eq!(genuine[0], GENUINE_SERIAL);

    // The genuine track is the only one that moves: its Location speed is > 0.
    let moving = frames
        .iter()
        .filter_map(|f| match &f.message {
            Message::Location(l) => l.speed_horizontal,
            _ => None,
        })
        .any(|s| s > 0.0);
    assert!(moving, "the genuine track must have non-zero ground speed");
}

#[test]
fn ridf_round_trips_through_remoteid_decoder() {
    let scenario = Scenario::new(ScenarioKind::Flood, 25);
    let frames = generate(&scenario);
    let writer = ScenarioWriter::new(frames.clone());

    let mut ridf = Vec::new();
    writer.to_ridf(&mut ridf).unwrap();
    assert!(ridf.starts_with(b"RIDF"), "RIDF file header expected");

    // Decode the file back with remoteid's capture reader.
    let decoded = capture::frames(&ridf).expect("remoteid decodes the generated RIDF");
    assert_eq!(
        decoded.len(),
        frames.len(),
        "every generated frame must come back"
    );

    for (orig, back) in frames.iter().zip(decoded.iter()) {
        let want = orig.message.encode().unwrap();
        assert_eq!(
            back.payload.as_slice(),
            want.as_slice(),
            "payload must round-trip byte for byte"
        );
        // And the payload decodes to the same message.
        let remsg = Message::decode(&back.payload).unwrap();
        assert_eq!(remsg, orig.message, "message must round-trip");
        assert_eq!(back.transmitter, orig.transmitter);
        assert_eq!(back.counter, Some(orig.counter));
    }
}

#[test]
fn pcap_round_trips_through_remoteid_decoder() {
    let scenario = Scenario::new(ScenarioKind::Clean, 4);
    let frames = generate(&scenario);
    let writer = ScenarioWriter::new(frames.clone());

    let mut pcap = Vec::new();
    writer.to_pcap(&mut pcap).unwrap();

    let decoded = capture::frames(&pcap).expect("remoteid decodes the generated pcap");
    assert_eq!(decoded.len(), frames.len(), "every frame must survive pcap");
    for (orig, back) in frames.iter().zip(decoded.iter()) {
        let remsg = Message::decode(&back.payload).unwrap();
        assert_eq!(remsg, orig.message, "pcap message must round-trip");
        assert_eq!(
            back.transmitter, orig.transmitter,
            "address must round-trip"
        );
    }
}

#[test]
fn jsonl_round_trips_through_serde() {
    let scenario = Scenario::new(ScenarioKind::Spoof, 1);
    let frames = generate(&scenario);
    let writer = ScenarioWriter::new(frames.clone());

    let mut jsonl = Vec::new();
    writer.to_jsonl(&mut jsonl).unwrap();
    let text = String::from_utf8(jsonl).unwrap();

    let lines: Vec<&str> = text.lines().collect();
    assert_eq!(lines.len(), frames.len(), "one JSON line per frame");
    for (line, orig) in lines.iter().zip(frames.iter()) {
        let rec: JsonlRecord = serde_json::from_str(line).unwrap();
        assert_eq!(
            rec.message, orig.message,
            "message must round-trip via serde"
        );
        assert_eq!(rec.counter, orig.counter);
        assert_eq!(rec.transmitter, orig.transmitter);
    }
}

#[test]
fn spoof_is_one_identity_from_two_transmitters() {
    let scenario = Scenario::new(ScenarioKind::Spoof, 1);
    let frames = generate(&scenario);

    let mut serials =
        basic_id_serials(&frames.iter().map(|f| f.message.clone()).collect::<Vec<_>>());
    serials.sort();
    serials.dedup();
    assert_eq!(serials.len(), 1, "spoof broadcasts one identity");

    let mut addrs: Vec<_> = frames.iter().map(|f| f.transmitter).collect();
    addrs.sort();
    addrs.dedup();
    assert_eq!(
        addrs.len(),
        2,
        "that one identity comes from two transmitters"
    );
}

#[test]
fn every_scenario_generates_decodable_frames() {
    for kind in [
        ScenarioKind::Flood,
        ScenarioKind::Spoof,
        ScenarioKind::Clean,
        ScenarioKind::CountSpike,
        ScenarioKind::Colocated,
    ] {
        let frames = generate(&Scenario::new(kind, 10));
        assert!(!frames.is_empty(), "{} produced no frames", kind.name());
        for f in &frames {
            let encoded = f.message.encode().expect("message encodes");
            let decoded = Message::decode(&encoded).expect("message decodes");
            assert_eq!(decoded, f.message, "{} frame must round-trip", kind.name());
        }
    }
}
