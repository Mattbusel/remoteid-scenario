//! Scenario configuration: the knobs that describe a synthetic Remote ID
//! airspace. These are plain data types; nothing here touches radio, and
//! nothing here emits bytes. A [`Scenario`] is turned into an in-memory
//! stream of decoded messages by [`crate::generate`].

use serde::{Deserialize, Serialize};

/// Which synthetic airspace to build. See the crate docs for what each one
/// is meant to prove about a detector under test.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScenarioKind {
    /// One source address emitting hundreds of templated fake IDs plus one
    /// embedded genuine moving track. The reference scenario: find the real
    /// drone in the crowd.
    Flood,
    /// A single cloned identity broadcast from two transmitters at
    /// incompatible positions. One fake, to prove per-unit spoof detection.
    Spoof,
    /// A baseline of a few honest drones from distinct sources. A detector
    /// must flag this as clear with no false positives.
    Clean,
    /// Many transmitters appearing within one second from distinct synthetic
    /// addresses, to exercise the onset / count-spike path.
    CountSpike,
    /// Several tracks sharing one identical operator position and a tight
    /// position / RSSI cluster, to exercise co-location aggregates.
    Colocated,
}

impl ScenarioKind {
    /// Parses the lower-case name used on the command line.
    pub fn from_name(s: &str) -> Option<ScenarioKind> {
        Some(match s {
            "flood" => ScenarioKind::Flood,
            "spoof" => ScenarioKind::Spoof,
            "clean" => ScenarioKind::Clean,
            "count_spike" | "count-spike" => ScenarioKind::CountSpike,
            "colocated" | "co-located" => ScenarioKind::Colocated,
            _ => return None,
        })
    }

    /// The lower-case name.
    pub fn name(self) -> &'static str {
        match self {
            ScenarioKind::Flood => "flood",
            ScenarioKind::Spoof => "spoof",
            ScenarioKind::Clean => "clean",
            ScenarioKind::CountSpike => "count_spike",
            ScenarioKind::Colocated => "colocated",
        }
    }
}

/// How a fake unit's serial numbers are built. The manufacturer code and
/// body are checked so every serial is a valid ANSI/CTA-2063-A string the
/// detector will actually parse.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SerialTemplate {
    /// Four character ICAO manufacturer code (digits and upper case, no O or I).
    pub manufacturer_code: String,
    /// Fixed prefix in front of the per-unit suffix.
    pub prefix: String,
    /// When true, the suffix counts up per unit; when false every fake shares
    /// `fixed_suffix` (an even cruder clone a detector should still catch).
    pub sequential: bool,
    /// The shared suffix used when `sequential` is false.
    pub fixed_suffix: String,
}

impl Default for SerialTemplate {
    fn default() -> Self {
        SerialTemplate {
            manufacturer_code: "1581".to_string(),
            prefix: "FAKE".to_string(),
            sequential: true,
            fixed_suffix: "0001".to_string(),
        }
    }
}

/// The one genuine moving track embedded in a flood. Sane kinematics, a
/// distinct serial and its own signal strength.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GenuineTrack {
    /// ANSI/CTA-2063-A serial of the real drone.
    pub serial: String,
    /// Start latitude, degrees.
    pub start_lat: f64,
    /// Start longitude, degrees.
    pub start_lon: f64,
    /// Track over ground, degrees clockwise from true north.
    pub heading_deg: f32,
    /// Ground speed, metres per second.
    pub speed_mps: f32,
    /// Signal strength of the real track, dBm.
    pub rssi_dbm: i8,
}

impl Default for GenuineTrack {
    fn default() -> Self {
        GenuineTrack {
            serial: "1581CREAL7A4F2C91".to_string(),
            start_lat: 40.7128,
            start_lon: -74.0060,
            heading_deg: 90.0,
            speed_mps: 12.0,
            rssi_dbm: -58,
        }
    }
}

/// Timing of the emitted stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Timing {
    /// Broadcast frames per second per unit (each 25 byte message is one frame).
    pub frames_per_s: u32,
    /// Length of the capture window, seconds.
    pub window_s: u32,
}

impl Default for Timing {
    fn default() -> Self {
        Timing {
            frames_per_s: 2,
            window_s: 10,
        }
    }
}

/// How the fake message counters behave. Real transmitters count up by one
/// per frame; the other two modes are spoof tells.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CounterMode {
    /// Counts up by one per frame, wrapping at 255 (a genuine transmitter).
    Honest,
    /// Never changes (a crude replay / spoof).
    Frozen,
    /// Every fake advances in lockstep, so hundreds of "drones" share one
    /// counter value at every instant (a templated flood).
    Lockstep,
}

/// How the fake transmitters address themselves on the air.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AddressMode {
    /// Every fake shares one radio address.
    Shared,
    /// Each fake gets its own distinct synthetic address.
    PerUnit,
}

/// The transmitter model for the fake units.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceModel {
    /// Shared or per-unit radio address.
    pub address_mode: AddressMode,
    /// When true, all fakes report one shared Wi-Fi TSF value (recorded in
    /// the RIDF beacon extension); real units each have their own.
    pub shared_tsf: bool,
    /// Counter behaviour of the fakes.
    pub counter_mode: CounterMode,
}

/// A latitude / longitude the operator claims to be at.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct OperatorPosition {
    /// Latitude, degrees.
    pub lat: f64,
    /// Longitude, degrees.
    pub lon: f64,
}

/// A full scenario description.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Scenario {
    /// Which airspace to build.
    pub kind: ScenarioKind,
    /// Number of fake units (ignored by `clean`, which uses `fake_count` as
    /// the number of honest drones instead).
    pub fake_count: u32,
    /// Serial template for the fakes.
    pub template: SerialTemplate,
    /// The embedded genuine track (used by `flood`; ignored elsewhere).
    pub genuine: GenuineTrack,
    /// Timing of the stream.
    pub timing: Timing,
    /// Transmitter model for the fakes.
    pub source: SourceModel,
    /// The operator position the fakes all claim.
    pub operator: OperatorPosition,
}

impl Scenario {
    /// A sensible default scenario for `kind`, with `fake_count` units.
    pub fn new(kind: ScenarioKind, fake_count: u32) -> Scenario {
        let counter_mode = match kind {
            ScenarioKind::Flood => CounterMode::Lockstep,
            ScenarioKind::Spoof => CounterMode::Frozen,
            _ => CounterMode::Honest,
        };
        let address_mode = match kind {
            ScenarioKind::Flood => AddressMode::Shared,
            _ => AddressMode::PerUnit,
        };
        Scenario {
            kind,
            fake_count,
            template: SerialTemplate::default(),
            genuine: GenuineTrack::default(),
            timing: Timing::default(),
            source: SourceModel {
                address_mode,
                shared_tsf: matches!(kind, ScenarioKind::Flood),
                counter_mode,
            },
            operator: OperatorPosition {
                lat: 40.7121,
                lon: -74.0070,
            },
        }
    }
}
