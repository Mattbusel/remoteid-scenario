# remoteid-scenario

Test-vector generator for counter-UAS detectors. It writes spec-compliant
Remote ID message streams to a file or stdout so you can pipe a synthetic
flood, spoof or clean baseline into your detection software and prove the
detector reacts the way it should.

This is a bench harness, not a sensor and not a transmitter. It is to a
counter-UAS detector what a fuzzer corpus or the EICAR test file is to the
software it exercises: known inputs with a known right answer, so you can
regression-test the thing that is supposed to catch them.

It builds every frame with the published
[`remoteid`](https://crates.io/crates/remoteid) 0.3.3 encoders, the same ones
that encode frames for firmware, and aims them at a file instead of a radio.
Nothing on the RF side is new here.

## Hard boundaries

This crate is **data only**. Read this before you use it.

- **No radio.** It never opens an SDR, a Bluetooth or Wi-Fi adapter, or any
  other device.
- **No transmit path.** It never broadcasts. Every byte it produces goes to a
  file or a pipe, for a software detector to read back.
- **No BLE / Wi-Fi / SDR / HackRF / ESP32 / nRF support**, and no firmware
  flashing.
- **No instructions for broadcasting into real airspace**, and **no evasion
  guidance**.

The output exists to test a detector you control, on the bench. If a change
would add a transmit or broadcast capability, it does not belong in this
crate; stop and raise it instead.

## Install

```
cargo add remoteid-scenario
```

or build the bundled binary:

```
cargo build --release
```

## Command line

```
remoteid-scenario <scenario> [--count N] [--format ridf|pcap|jsonl] [--out PATH]
                             [--fps N] [--window N]
```

Examples:

```
# A 500-strong flood with one real drone hidden in it, as RIDF, to a file.
remoteid-scenario flood --count 500 --out flood.ridf

# A single cloned identity as JSON lines, to stdout, to eyeball.
remoteid-scenario spoof --format jsonl

# A clean baseline of 6 honest drones as a pcap for your pipeline.
remoteid-scenario clean --count 6 --format pcap --out clean.pcap
```

Omit `--out`, or pass `-`, to write to stdout.

## Scenarios

| name          | what it builds                                                                                                   | a detector should...                                  |
|---------------|------------------------------------------------------------------------------------------------------------------|-------------------------------------------------------|
| `flood`       | one source address emitting hundreds of templated fakes (shared MAC, sequential serials, lockstep or frozen counters, identical operator position) **plus one genuine moving track** with a distinct serial, sane kinematics and its own RSSI | flag the flood **and point at the one real drone**    |
| `spoof`       | a single cloned identity broadcast from two transmitters at incompatible positions                                | flag per-unit spoofing (identity clone / disagreement) |
| `clean`       | a few honest drones from distinct sources: real MACs, valid serials, consistent moving tracks                     | report **Clear**, with no false positives             |
| `count_spike` | many transmitters appearing within one second from distinct synthetic addresses                                   | fire the onset / count-spike path                      |
| `colocated`   | several tracks sharing one operator position and a tight position / RSSI cluster                                  | fire the co-location aggregates                        |

`flood` is the reference scenario: find the real drone in the crowd.

## Output formats

- **`ridf`** (default): remoteid's native RIDF capture format. This is the
  format the companion analyzer re-ingests directly, and it carries receiver
  time, signal strength, the message counter and the modelled TSF.
- **`pcap`**: a classic pcap of Bluetooth LE link-layer advertising packets
  (link type 251, `LINKTYPE_BLUETOOTH_LE_LL`). Each packet is a real
  `ADV_NONCONN_IND` carrying the Remote ID service data, so any pcap reader
  decodes it back to the same message.
- **`jsonl`**: one decoded message per line, with its transmitter, counter,
  RSSI and timestamp. Easy to diff and to eyeball.

Every format round-trips: the frames decode back through remoteid's own
decoders to the exact messages that were generated. The test suite asserts it.

## As a library

```rust
use remoteid_scenario::{generate, Scenario, ScenarioKind, ScenarioWriter};

let scenario = Scenario::new(ScenarioKind::Flood, 500);
let frames = generate(&scenario);
let writer = ScenarioWriter::new(frames);

let mut file = std::fs::File::create("flood.ridf").unwrap();
writer.to_ridf(&mut file).unwrap();
```

`Scenario` exposes every knob: `SerialTemplate` (manufacturer code, prefix,
sequential or fixed suffix), the embedded `GenuineTrack`, `Timing`
(frames per second, window), the `SourceModel` (shared or per-unit address,
shared TSF, counter mode: honest / frozen / lockstep), and the operator
position.

## What is deferred

Out of scope for now, by design:

- live replay timing (frames are stamped, not slept between),
- real pcap radiotap / Wi-Fi L2 framing beyond the BLE advertising packets
  above,
- DJI / OcuSync synthesis.

None of these is a transmit path, and none will be added here.

## License

MIT OR Apache-2.0.
