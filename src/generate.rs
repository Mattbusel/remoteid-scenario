//! Turning a [`Scenario`] into an in-memory stream of decoded Remote ID
//! messages.
//!
//! This module never touches a radio. It builds exactly the
//! [`remoteid::Message`] values a firmware transmitter would encode, tags
//! each with its intended transmitter, counter, timestamp and signal
//! strength, and hands the list back. The writers in [`crate::writer`] then
//! serialise that list to a file or stdout. Nothing is broadcast.

use crate::config::{
    AddressMode, CounterMode, OperatorPosition, Scenario, ScenarioKind, SerialTemplate,
};
use remoteid::{
    BasicId, IdType, Location, Message, OperatorId, Status, System, Transmitter, Transport, UaType,
};

/// One synthetic frame: a single decoded message plus everything a receiver
/// would have observed about it. This is the unit the writers serialise.
#[derive(Debug, Clone, PartialEq)]
pub struct EmittedFrame {
    /// Capture time, microseconds from the stream's start epoch.
    pub time_us: u64,
    /// The transmitter the frame is attributed to.
    pub transmitter: Transmitter,
    /// The radio link it is modelled on (always Bluetooth 4 here).
    pub transport: Transport,
    /// The message counter the frame carries.
    pub counter: u8,
    /// The decoded Remote ID message.
    pub message: Message,
    /// Signal strength, dBm.
    pub rssi_dbm: i8,
    /// Modelled Wi-Fi TSF, when the source model records one. Carried in the
    /// RIDF beacon extension so a TSF-aware analyzer can see shared vs
    /// distinct timing. The frames themselves are modelled as BLE broadcasts.
    pub tsf: Option<u64>,
}

/// Start epoch for the stream, microseconds since the Unix epoch
/// (2024-06-01 00:00:00 UTC). A fixed, obviously-synthetic time.
const START_US: u64 = 1_717_200_000_000_000;

const METERS_PER_DEG: f64 = 111_320.0;

/// Builds the full frame stream for `scenario`.
pub fn generate(scenario: &Scenario) -> Vec<EmittedFrame> {
    match scenario.kind {
        ScenarioKind::Flood => flood(scenario),
        ScenarioKind::Spoof => spoof(scenario),
        ScenarioKind::Clean => clean(scenario),
        ScenarioKind::CountSpike => count_spike(scenario),
        ScenarioKind::Colocated => colocated(scenario),
    }
}

/// A valid ANSI/CTA-2063-A serial from a manufacturer code and a body.
/// Only digits and upper-case letters (no `O` or `I`) survive; the length
/// character is derived so the string parses.
fn make_serial(manufacturer_code: &str, body: &str) -> String {
    let clean_body: String = body
        .chars()
        .map(|c| c.to_ascii_uppercase())
        .filter(|&c| (c.is_ascii_digit() || c.is_ascii_uppercase()) && c != 'O' && c != 'I')
        .take(15)
        .collect();
    let clean_body = if clean_body.is_empty() {
        "X".to_string()
    } else {
        clean_body
    };
    let len = clean_body.len() as u8;
    let len_char = if len <= 9 {
        (b'0' + len) as char
    } else {
        (b'A' + (len - 10)) as char
    };
    let mut code: String = manufacturer_code
        .chars()
        .filter(|&c| (c.is_ascii_digit() || c.is_ascii_uppercase()) && c != 'O' && c != 'I')
        .take(4)
        .collect();
    while code.len() < 4 {
        code.push('1');
    }
    format!("{code}{len_char}{clean_body}")
}

/// Returns `s` unchanged when it already parses as an ANSI/CTA-2063-A
/// serial, otherwise builds a valid one from it under manufacturer code 1581.
fn ensure_serial(s: &str) -> String {
    let parses = BasicId::new(IdType::SerialNumber, UaType::None, s)
        .ok()
        .and_then(|b| b.serial_number().map(|_| ()))
        .is_some();
    if parses {
        s.to_string()
    } else {
        make_serial("1581", s)
    }
}

fn template_serial(template: &SerialTemplate, index: u32) -> String {
    let body = if template.sequential {
        format!("{}{:05}", template.prefix, index)
    } else {
        format!("{}{}", template.prefix, template.fixed_suffix)
    };
    make_serial(&template.manufacturer_code, &body)
}

/// A six byte radio address from a seed. Locally-administered unicast bit
/// pattern, all obviously synthetic.
fn address(seed: u32) -> [u8; 6] {
    let b = seed.to_be_bytes();
    [0x02, 0x00, b[0], b[1], b[2], b[3]]
}

/// Moves a lat/lon by `speed` m/s along `heading` (degrees from north) for
/// `dt` seconds. Equirectangular, good enough for a few-kilometre window.
fn advance(lat: f64, lon: f64, heading_deg: f32, speed_mps: f32, dt_s: f64) -> (f64, f64) {
    let h = (heading_deg as f64).to_radians();
    let north_m = speed_mps as f64 * dt_s * h.cos();
    let east_m = speed_mps as f64 * dt_s * h.sin();
    let dlat = north_m / METERS_PER_DEG;
    let dlon = east_m / (METERS_PER_DEG * lat.to_radians().cos().abs().max(1e-6));
    (lat + dlat, lon + dlon)
}

/// Builds the four-message cycle for one unit at one instant: Basic ID,
/// Location, System, Operator ID.
struct Unit<'a> {
    serial: &'a str,
    operator_id: &'a str,
    transmitter: Transmitter,
    lat: f64,
    lon: f64,
    heading_deg: f32,
    speed_mps: f32,
    operator: OperatorPosition,
    status: Status,
    rssi_dbm: i8,
    tsf: Option<u64>,
    area_count: u16,
}

fn basic_id(serial: &str) -> Message {
    Message::BasicId(
        BasicId::new(IdType::SerialNumber, UaType::HelicopterOrMultirotor, serial)
            .expect("serial fits in 20 bytes"),
    )
}

fn location_msg(unit: &Unit, altitude: f32) -> Message {
    let mut loc = Location {
        status: unit.status,
        latitude: unit.lat,
        longitude: unit.lon,
        altitude_geo: Some(altitude),
        height: Some(altitude),
        ..Location::default()
    };
    if unit.speed_mps > 0.0 {
        loc.direction = Some(unit.heading_deg % 360.0);
        loc.speed_horizontal = Some(unit.speed_mps);
    } else {
        loc.direction = Some(0.0);
        loc.speed_horizontal = Some(0.0);
    }
    loc.speed_vertical = Some(0.0);
    Message::Location(loc)
}

fn system_msg(unit: &Unit) -> Message {
    Message::System(System {
        operator_latitude: unit.operator.lat,
        operator_longitude: unit.operator.lon,
        area_count: unit.area_count,
        operator_altitude_geo: Some(0.0),
        ..System::default()
    })
}

fn operator_msg(operator_id: &str) -> Message {
    Message::OperatorId(OperatorId::new(operator_id).expect("operator id fits in 20 bytes"))
}

/// Normalises a message to the on-the-wire grid: exactly the value a
/// receiver decodes after the quantized broadcast encoding. Storing this
/// form means the emitted message equals what a detector sees, byte for byte.
fn canonical(message: Message) -> Message {
    match message.encode() {
        Ok(bytes) => Message::decode(&bytes).unwrap_or(message),
        Err(_) => message,
    }
}

/// Pushes one unit's four frames at `time_us` with `counter`.
fn push_cycle(out: &mut Vec<EmittedFrame>, unit: &Unit, time_us: u64, counter: u8, altitude: f32) {
    for message in [
        basic_id(unit.serial),
        location_msg(unit, altitude),
        system_msg(unit),
        operator_msg(unit.operator_id),
    ] {
        out.push(EmittedFrame {
            time_us,
            transmitter: unit.transmitter,
            transport: Transport::Bluetooth4,
            counter,
            message: canonical(message),
            rssi_dbm: unit.rssi_dbm,
            tsf: unit.tsf,
        });
    }
}

fn counter_value(mode: CounterMode, tick: u32, per_unit: u32) -> u8 {
    match mode {
        CounterMode::Honest => (per_unit & 0xFF) as u8,
        CounterMode::Frozen => 0,
        CounterMode::Lockstep => (tick & 0xFF) as u8,
    }
}

fn flood(s: &Scenario) -> Vec<EmittedFrame> {
    let mut out = Vec::new();
    let ticks = s.timing.frames_per_s * s.timing.window_s;
    let dt_us = 1_000_000u64 / s.timing.frames_per_s.max(1) as u64;
    let shared_addr = address(0xF0_00);
    let shared_tsf = if s.source.shared_tsf {
        Some(0x0011_2233_4455_6677u64)
    } else {
        None
    };

    // The templated fakes: shared address, identical operator position, a
    // frozen location, sequential serials, lockstep or frozen counters.
    for tick in 0..ticks {
        let time_us = START_US + tick as u64 * dt_us;
        for i in 0..s.fake_count {
            let serial = template_serial(&s.template, i);
            let transmitter = match s.source.address_mode {
                AddressMode::Shared => Transmitter::Ble(shared_addr),
                AddressMode::PerUnit => Transmitter::Ble(address(0x1000 + i)),
            };
            let unit = Unit {
                serial: &serial,
                operator_id: "OP-FLOOD-SPOOFER",
                transmitter,
                lat: s.operator.lat + 0.0005,
                lon: s.operator.lon + 0.0005,
                heading_deg: 0.0,
                speed_mps: 0.0,
                operator: s.operator,
                status: Status::Airborne,
                rssi_dbm: -50,
                tsf: shared_tsf,
                area_count: 1,
            };
            let counter = counter_value(s.source.counter_mode, tick, tick);
            push_cycle(&mut out, &unit, time_us, counter, 60.0);
        }
    }

    // The one embedded genuine track: distinct serial and address, honest
    // counter, sane moving kinematics, its own RSSI and its own TSF.
    let g = &s.genuine;
    let genuine_serial = ensure_serial(&g.serial);
    let genuine_addr = Transmitter::Ble(address(0x7777));
    for tick in 0..ticks {
        let time_us = START_US + tick as u64 * dt_us;
        let dt_s = tick as f64 * dt_us as f64 / 1_000_000.0;
        let (lat, lon) = advance(g.start_lat, g.start_lon, g.heading_deg, g.speed_mps, dt_s);
        let unit = Unit {
            serial: &genuine_serial,
            operator_id: "OP-REAL-OPERATOR01",
            transmitter: genuine_addr,
            lat,
            lon,
            heading_deg: g.heading_deg,
            speed_mps: g.speed_mps,
            operator: OperatorPosition {
                lat: g.start_lat - 0.0003,
                lon: g.start_lon - 0.0003,
            },
            status: Status::Airborne,
            rssi_dbm: g.rssi_dbm,
            tsf: Some(0x00AA_BBCC_DD00_0000 + tick as u64),
            area_count: 1,
        };
        push_cycle(
            &mut out,
            &unit,
            time_us,
            (tick & 0xFF) as u8,
            80.0 + tick as f32,
        );
    }
    out
}

fn spoof(s: &Scenario) -> Vec<EmittedFrame> {
    // One identity, two transmitters, two incompatible positions.
    let mut out = Vec::new();
    let ticks = s.timing.frames_per_s * s.timing.window_s;
    let dt_us = 1_000_000u64 / s.timing.frames_per_s.max(1) as u64;
    let serial = make_serial(
        &s.template.manufacturer_code,
        &format!("{}CLONE", s.template.prefix),
    );

    let legs = [
        (Transmitter::Ble(address(0xA1)), 40.7128, -74.0060, -55i8),
        (Transmitter::Ble(address(0xB2)), 40.9000, -73.8000, -72i8),
    ];
    for tick in 0..ticks {
        let time_us = START_US + tick as u64 * dt_us;
        for (transmitter, lat, lon, rssi) in legs {
            let unit = Unit {
                serial: &serial,
                operator_id: "OP-CLONE-TARGET001",
                transmitter,
                lat,
                lon,
                heading_deg: 0.0,
                speed_mps: 0.0,
                operator: s.operator,
                status: Status::Airborne,
                rssi_dbm: rssi,
                tsf: None,
                area_count: 1,
            };
            let counter = counter_value(s.source.counter_mode, tick, tick);
            push_cycle(&mut out, &unit, time_us, counter, 100.0);
        }
    }
    out
}

fn clean(s: &Scenario) -> Vec<EmittedFrame> {
    // A few honest drones from distinct sources, each moving sanely.
    let mut out = Vec::new();
    let count = s.fake_count.max(1);
    let ticks = s.timing.frames_per_s * s.timing.window_s;
    let dt_us = 1_000_000u64 / s.timing.frames_per_s.max(1) as u64;
    for i in 0..count {
        let serial = make_serial("1581", &format!("HONEST{:04}", i));
        let transmitter = Transmitter::Ble(address(0x3000 + i));
        let start_lat = 40.7128 + i as f64 * 0.01;
        let start_lon = -74.0060 - i as f64 * 0.01;
        let heading = 45.0 + i as f32 * 30.0;
        let speed = 8.0 + i as f32;
        for tick in 0..ticks {
            let time_us = START_US + tick as u64 * dt_us;
            let dt_s = tick as f64 * dt_us as f64 / 1_000_000.0;
            let (lat, lon) = advance(start_lat, start_lon, heading, speed, dt_s);
            let unit = Unit {
                serial: &serial,
                operator_id: "OP-LICENSED-FLYER1",
                transmitter,
                lat,
                lon,
                heading_deg: heading,
                speed_mps: speed,
                operator: OperatorPosition {
                    lat: start_lat - 0.0002,
                    lon: start_lon - 0.0002,
                },
                status: Status::Airborne,
                rssi_dbm: -60 - i as i8,
                tsf: Some(
                    0x0100_0000_0000_0000u64.wrapping_mul(1) + i as u64 * 0x1000 + tick as u64,
                ),
                area_count: 1,
            };
            push_cycle(
                &mut out,
                &unit,
                time_us,
                (tick & 0xFF) as u8,
                50.0 + tick as f32,
            );
        }
    }
    out
}

fn count_spike(s: &Scenario) -> Vec<EmittedFrame> {
    // Many transmitters appearing within one second, distinct addresses,
    // minimal templating.
    let mut out = Vec::new();
    let count = s.fake_count.max(1);
    for i in 0..count {
        // Spread arrivals across the first second.
        let time_us = START_US + (i as u64 * 1_000_000 / count as u64);
        let serial = make_serial("1581", &format!("SPIKE{:05}", i));
        let unit = Unit {
            serial: &serial,
            operator_id: "OP-SPIKE-SOURCE001",
            transmitter: Transmitter::Ble(address(0x5000 + i)),
            lat: s.operator.lat + (i as f64 % 20.0) * 0.0001,
            lon: s.operator.lon + (i as f64 % 20.0) * 0.0001,
            heading_deg: 0.0,
            speed_mps: 0.0,
            operator: s.operator,
            status: Status::Airborne,
            rssi_dbm: -55,
            tsf: None,
            area_count: 1,
        };
        push_cycle(&mut out, &unit, time_us, 0, 40.0);
    }
    out
}

fn colocated(s: &Scenario) -> Vec<EmittedFrame> {
    // Several tracks sharing one operator position and a tight position /
    // RSSI cluster.
    let mut out = Vec::new();
    let count = s.fake_count.max(1);
    let ticks = s.timing.frames_per_s * s.timing.window_s;
    let dt_us = 1_000_000u64 / s.timing.frames_per_s.max(1) as u64;
    for i in 0..count {
        let serial = make_serial("1581", &format!("CLUSTER{:03}", i));
        for tick in 0..ticks {
            let time_us = START_US + tick as u64 * dt_us;
            let unit = Unit {
                serial: &serial,
                operator_id: "OP-COLOCATED-GROUP",
                transmitter: Transmitter::Ble(address(0x6000 + i)),
                // Tight cluster: a few metres apart.
                lat: s.operator.lat + 0.0003 + i as f64 * 0.00002,
                lon: s.operator.lon + 0.0003 + i as f64 * 0.00002,
                heading_deg: 0.0,
                speed_mps: 0.0,
                operator: s.operator,
                status: Status::Airborne,
                rssi_dbm: -52,
                tsf: None,
                area_count: count as u16,
            };
            push_cycle(&mut out, &unit, time_us, (tick & 0xFF) as u8, 70.0);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serials_parse() {
        let s = make_serial("1581", "FAKE00007");
        let bid = BasicId::new(IdType::SerialNumber, UaType::None, &s).unwrap();
        assert!(bid.serial_number().is_some(), "built serial {s} must parse");
    }

    #[test]
    fn make_serial_strips_forbidden() {
        let s = make_serial("1581", "boO-iI 9"); // lowercase, O, I, space, dash
        let bid = BasicId::new(IdType::SerialNumber, UaType::None, &s).unwrap();
        assert!(
            bid.serial_number().is_some(),
            "sanitised serial {s} must parse"
        );
    }
}
