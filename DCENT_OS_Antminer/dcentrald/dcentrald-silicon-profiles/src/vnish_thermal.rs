//! Rank-31 (2026-08-03): VNish 1.2.7 thermal/hardware matrix — 77 models,
//! declarative descriptor rows.
//!
//! # What this is
//!
//! A declarative per-model registry of the VNish 1.2.7 thermal/hardware
//! matrix, keyed by Bitmain `btm_model` string. It extends the registry
//! pattern of [`crate::hashboard_topology`] (ePIC jig DB, 50 SKUs) and
//! [`crate::sensor_topology`] with a **second, independent desk corpus**:
//! the model JSONs shipped inside 18 VNish 1.2.7 firmware images
//! (`hwscan --gen-model-info`, re-armada 2026-04-25 extraction).
//!
//! **This module is data + accounting ONLY.** Nothing here is wired into any
//! thermal control, throttle, fan curve, PID, or mining path. The declared
//! thresholds are *what VNish ships*, recorded as competitive/RE evidence —
//! they are NOT DCENT policy and MUST NOT be consumed as safety limits.
//!
//! # Provenance — THIRD-PARTY TRANSCRIPTION, Experimental
//!
//! Every row carries [`DescriptorProvenance::DeskVnishFirmwareExperimental`]:
//! VNish transcribed Bitmain's data; we transcribed VNish's images. Two rules
//! travel with every consumer:
//!
//! 1. **A DCENT live measurement always outranks this matrix.**
//! 2. **This matrix never overwrites the ePIC-transcribed registry** (and
//!    vice versa). Where the two desk corpora contradict each other the
//!    conflict is recorded below and pinned in
//!    `tests/vnish_thermal_matrix.rs`, not resolved by guessing.
//!
//! # Source-consensus contract (fail-closed at generation time)
//!
//! The source CSV has 1,386 rows = 77 models × 18 firmware images. The
//! generator REFUSES (asserts) unless every model (a) appears exactly once
//! per image and (b) is byte-identical across all 18 images on every
//! imported field. Both held: the only cross-image variance in the whole
//! corpus is the `platform` column (a property of the firmware image, not
//! the model), folded into [`VnishModelDescriptor::observed_platforms`].
//! Absent values are empty in the source and become `None` here — never a
//! plausible default (the 25 hydro/immersion models genuinely ship with no
//! `auto`/`manual` cooling block).
//!
//! # Deliberately NOT imported (refused, not forgotten)
//!
//! - `psu_max_volt` / `psu_min_volt` / `psu_modded_max_volt` / `psu_models`
//!   (PSU voltage envelope + PSU model ID lists), and
//! - `default_freq` / `default_volt` / `warn_freq` / `max_freq` / `min_freq`
//!   (per-model tuning presets).
//!
//! Same posture as [`crate::hashboard_topology`]'s refusal of the ePIC
//! `power`/`strategy` blocks: third-party tuning presets are the "wrong
//! calibration worse than none" class, and a checked-in frequency/voltage
//! number WILL eventually be mistaken for DCENT policy. They stay in the
//! source docs (`temp-sensor-matrix.md`, `default-settings-matrix.md`,
//! `power-*.md`) where their VNish framing is unambiguous. `chip_type` is
//! empty on all 1,386 source rows and is likewise not modeled.
//!
//! # Known cross-corpus findings (recorded, neither side overwritten)
//!
//! Of the 77 models, **36 overlap** the ePIC jig registry and **41 are new**
//! (all HHB/H6HB/H1HB/IHB/M1HB hydro-immersion boards, the L7/L9 scrypt
//! boards, NBS/NBT/BHB28xxx S19a/S19i/T19-era boards, and the placeholder
//! IDs `42801`/`BHBXXXX`/`BHBXXXXX`/`HHBXXX`).
//!
//! - **Corroborations (36/36):** `chips_per_chain`, `chips_per_domain`, and
//!   `domains_per_chain` agree EXACTLY with the ePIC registry on every
//!   overlapping SKU. Two independent transcriptions of the same upstream
//!   data agreeing is meaningful desk evidence.
//! - **Chains conflict (14 SKUs):** VNish says `chains = 3` on every
//!   BHB42xxx/NBP1901/NBS1902 row where ePIC says `chains_per_unit = 4`.
//!   VNish agrees with DCENT live evidence (S19j Pro / S19 Pro units `a lab unit`,
//!   `a lab unit`, `a lab unit` all have 3 hashboard slots) — which supports the
//!   existing adjudication that the ePIC `4` is a jig-fixture value. The
//!   ePIC row is imported-verbatim by design and is NOT rewritten.
//! - **A3HB70701 sensor contradiction:** VNish declares 4 sensors
//!   `via-bus-switch` at `0x4C`; the ePIC row declares 4 DIRECT sensors at
//!   `0x48..=0x4B` and NO switch bank. Unresolvable at the desk; pinned.
//! - **Mux-bank subset (6 SKUs):** on A3HB705xx/A3HB706xx (S21 Pro/XP),
//!   VNish's 4×`0x4C` via-bus-switch roster matches the ePIC `switchsensor`
//!   bank exactly — but VNish does NOT list the 4-sensor direct bank the
//!   ePIC DB also declares there. Under-report vs. superset; recorded.
//! - **2-sensor rows (24 SKUs):** VNish's modern `direct` pair
//!   (`0x48`+`0x4C`) is 2 sensors where the ePIC board bank declares 4 at
//!   `0x48..=0x4B` (plus a ctrl-board pair at `0x48`/`0x4C`). The two
//!   corpora model different things (runtime-read roster vs. board wiring);
//!   recorded, not adjudicated.
//! - **`chip_temp_offset` is NOT universally 15.** The corpus census is
//!   15 °C on 63 models, 0 °C on 6, 10 °C on 5, 5 °C on 3 — the
//!   "universal 15" claim in `temp-sensor-matrix.md`'s prose is falsified
//!   by its own CSV. The CSV is authoritative for this import.
//! - **`BHB68709` declares two sensors at the SAME address** (`0x4C,0x4C`,
//!   access `direct`) — physically ambiguous as flat wiring; imported
//!   verbatim and pinned as a transcription oddity.
//! - **`0x98` sensor "addresses"** (L7, S19a/S19a Pro, S19/T19 Hydro rows)
//!   are not valid 7-bit addresses. Per the source doc's own IC table,
//!   `0x98` is the 8-bit write form of `0x4C` used by VNish for
//!   ASIC-internal I²C-passthrough sensors. Imported verbatim as `0x98`
//!   (never normalized — that would be a guess about VNish's encoding).
//!
//! # Why these rows do NOT become [`crate::sensor_topology::SensorSpec`]s
//!
//! `SensorSpec` requires a quadrant position (`left|right` × `top|bottom`)
//! and a device identity; the VNish matrix carries only a coarse
//! `front|middle|back` location and no device name. Fabricating the missing
//! fields is forbidden, so this module keeps its own sensor declaration type
//! ([`VnishSensorDecl`]) and bridges to the shared coverage accounting via
//! [`VnishModelDescriptor::empty_board_sweep`] (a [`SensorSweep`] with the
//! declared per-board expectation and zero coverage).
//!
//! Similarly, [`VnishSensorAccess`] is deliberately separate from
//! [`crate::sensor_topology::SensorTransport`]: `SensorTransport` records
//! board-level *wiring* and deliberately refuses controller-routing claims,
//! while the VNish `access` field is precisely a *routing* claim
//! (`via-pic` / `via-chip-auto`). Folding one into the other would either
//! launder a routing claim into wiring authority or delete information.
//! `via-mixed` exists in VNish's schema but appears on zero of the 1,386
//! source rows, so it is NOT a variant here — an input claiming it must
//! fail closed (unknown-value refusal), not silently deserialize.
//!
//! # Schema range notes (why the integer widths are what they are)
//!
//! The corpus spans 2..=8 sensors, 3 or 4 chains, and up to 3×216 chips
//! (S21 Hydro — 648 chips/unit), with 4-chain hydro units reaching 4×180.
//! `chips_per_chain` is `u16`; per-unit totals use widened arithmetic.
//! `min_start_c` is negative (-30) on 62 models — temperatures are `i16`.
//!
//! # Regenerating the data file
//!
//! `src/vnish_thermal_matrix_1_2_7.json` is generated — do not hand-edit.
//! Regenerate from the repo root with (Python 3):
//!
//! ```text
//! python - <<'EOF'
//! import csv, json, collections
//! SRC = ''
//! OUT = 'DCENT_OS_Antminer/dcentrald/dcentrald-silicon-profiles/src/vnish_thermal_matrix_1_2_7.json'
//! ACCESS = {'direct': 'direct', 'via-pic': 'via_pic',
//!           'via-chip-auto': 'via_chip_auto', 'via-bus-switch': 'via_bus_switch'}
//! LOCATIONS = {'front', 'middle', 'back'}
//! MODES = {'auto', 'manual', 'immersion'}
//! CONSENSUS = ['series', 'name', 'model_code', 'chains', 'chips_per_chain',
//!              'cores_per_domain', 'num_domains', 'sensor_count', 'sensor_access',
//!              'sensor_addrs', 'sensor_locations', 'chip_temp_offset',
//!              'danger_chip_temp', 'hot_chip_temp', 'danger_board_temp',
//!              'normal_start_temp', 'min_start_temp',
//!              'auto_target_default', 'auto_target_min', 'auto_target_max',
//!              'manual_fan_default', 'manual_fan_min', 'manual_fan_max',
//!              'fan_min_count_default', 'fan_min_count_min', 'fan_min_count_max',
//!              'modes']
//! rows = list(csv.DictReader(open(SRC, encoding='utf-8')))
//! by_model = collections.defaultdict(list)
//! for r in rows:
//!     by_model[r['btm_model']].append(r)
//! fws = sorted(set(r['fw'] for r in rows))
//! assert len(fws) == 18, fws
//! models = []
//! for m in sorted(by_model):
//!     rs = by_model[m]
//!     assert len(rs) == 18, (m, len(rs))
//!     for f in CONSENSUS:
//!         vals = set(r[f] for r in rs)
//!         assert len(vals) == 1, f'AMBIGUOUS {m} {f}: {sorted(vals)}'
//!     r = rs[0]
//!     n = int(r['sensor_count'])
//!     addrs = [int(a, 16) for a in r['sensor_addrs'].split(',')]
//!     locs = r['sensor_locations'].split(',')
//!     assert len(addrs) == n and len(locs) == n, m
//!     assert all(l in LOCATIONS for l in locs), (m, locs)
//!     access = ACCESS[r['sensor_access']]  # KeyError = refuse (e.g. via-mixed)
//!     modes = r['modes'].split(',')
//!     assert modes and all(md in MODES for md in modes), (m, modes)
//!     def block(prefix):
//!         vals = [r[f'{prefix}_default'], r[f'{prefix}_min'], r[f'{prefix}_max']]
//!         if all(v == '' for v in vals):
//!             return None
//!         assert all(v != '' for v in vals), (m, prefix, vals)
//!         return {'default': int(vals[0]), 'min': int(vals[1]), 'max': int(vals[2])}
//!     auto = block('auto_target')
//!     manual = block('manual_fan')
//!     fmc = block('fan_min_count')
//!     assert (auto is not None) == ('auto' in modes), m
//!     assert (manual is not None) == ('manual' in modes), m
//!     chains = int(r['chains'])
//!     chips = int(r['chips_per_chain'])
//!     cpd = int(r['cores_per_domain'])
//!     nd = int(r['num_domains'])
//!     assert cpd * nd == chips, m
//!     models.append({
//!         'btm_model': m,
//!         'provenance': 'desk_vnish_firmware_experimental',
//!         'marketing_name': r['name'],
//!         'series': r['series'],
//!         'model_code': r['model_code'],
//!         'chains_per_unit': chains,
//!         'chips_per_chain': chips,
//!         'chips_per_domain': cpd,
//!         'domains_per_chain': nd,
//!         'sensor_access': access,
//!         'sensors': [{'i2c_addr': a, 'location': l} for a, l in zip(addrs, locs)],
//!         'limits': {'danger_chip_c': int(r['danger_chip_temp']),
//!                    'hot_chip_c': int(r['hot_chip_temp']),
//!                    'danger_board_c': int(r['danger_board_temp']),
//!                    'normal_start_c': int(r['normal_start_temp']),
//!                    'min_start_c': int(r['min_start_temp']),
//!                    'chip_temp_offset_c': int(r['chip_temp_offset'])},
//!         'cooling_modes': modes,
//!         'auto_target_c': auto,
//!         'manual_fan_pct': manual,
//!         'fan_min_count': fmc,
//!         'observed_platforms': sorted(set(x['platform'] for x in rs)),
//!     })
//! header = {
//!     'schema': 'dcent-vnish-thermal-matrix-v1',
//!     'source_csv': SRC,
//!     'source_matrix_doc': '',
//!     'roster_scope': 'VNish 1.2.7 firmware model JSONs (hwscan --gen-model-info), 18 images x 77 '
//!                     'models; THIRD-PARTY TRANSCRIPTION of Bitmain data by VNish; NOT a complete '
//!                     'Bitmain roster; never outranks a DCENT live measurement',
//!     'firmware_images': fws,
//!     'excluded_columns': ['chip_type (empty on all 1386 source rows)',
//!                          'platform (firmware property; folded into observed_platforms)',
//!                          'psu_max_volt/psu_min_volt/psu_modded_max_volt/psu_models '
//!                          '(PSU envelope: deliberately NOT imported)',
//!                          'default_freq/default_volt/warn_freq/max_freq/min_freq '
//!                          '(tuning presets: deliberately NOT imported)'],
//! }
//! with open(OUT, 'w', encoding='utf-8', newline='\n') as f:
//!     f.write('{\n')
//!     for k, v in header.items():
//!         f.write(json.dumps(k) + ': ' + json.dumps(v) + ',\n')
//!     f.write('"models": [\n')
//!     for i, b in enumerate(models):
//!         f.write(json.dumps(b, separators=(',', ':')) + (',\n' if i + 1 < len(models) else '\n'))
//!     f.write(']}\n')
//! print('wrote', OUT, len(models), 'models')
//! EOF
//! ```

use std::collections::HashMap;
use std::sync::OnceLock;

use serde::{Deserialize, Serialize};

use crate::hashboard_topology::DescriptorProvenance;
use crate::sensor_topology::SensorSweep;

/// The generated data file (see module docs for the generator command).
const MATRIX_JSON: &str = include_str!("vnish_thermal_matrix_1_2_7.json");

/// VNish's declared sensor access route. This is a **routing claim by
/// VNish**, deliberately kept separate from
/// [`crate::sensor_topology::SensorTransport`] (which records board wiring
/// and refuses routing claims). `via-mixed` exists in VNish's schema but is
/// observed on zero source rows, so it is intentionally NOT a variant —
/// serde fails closed on it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VnishSensorAccess {
    /// Kernel `/dev/i2c-N` directly to the sensor.
    Direct,
    /// Host I²C → hashboard PIC → sensor relay.
    ViaPic,
    /// Read through the ASIC's I²C-passthrough register.
    ViaChipAuto,
    /// Kernel I²C through a TCA9548A-class bus switch/mux.
    ViaBusSwitch,
}

impl VnishSensorAccess {
    /// `true` when reaching the sensors requires driving an I²C switch/mux
    /// — the same reachability caveat as
    /// [`crate::sensor_topology::SensorTransport::is_muxed`]: a reader that
    /// ignores the mux cannot count these sensors as covered.
    pub fn requires_bus_switch(&self) -> bool {
        matches!(self, VnishSensorAccess::ViaBusSwitch)
    }
}

/// Coarse sensor location along the board's airflow axis, as VNish spells
/// it. This is a DIFFERENT axis from the quadrant zones in
/// [`crate::sensor_topology::SensorPosition`] — the two are not
/// interconvertible without fabrication, which is why no conversion exists.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VnishSensorLocation {
    Front,
    /// Observed only on the 8-sensor S19/T19 Hydro rows (HHB28601/HHB28602).
    Middle,
    Back,
}

/// One declared temperature sensor: transcribed address + coarse location.
///
/// `i2c_addr` is VERBATIM from the source. Most values are 7-bit
/// (`0x48..=0x4C`), but `0x98` appears on ASIC-passthrough rows — per the
/// source doc's own IC table it is the 8-bit write form of `0x4C`. It is
/// NOT normalized here (that would be a guess about VNish's encoding);
/// [`Self::is_seven_bit_addr`] lets consumers separate the two classes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VnishSensorDecl {
    /// Transcribed address byte (see struct docs — not always 7-bit).
    pub i2c_addr: u8,
    /// Coarse location along the airflow axis.
    pub location: VnishSensorLocation,
}

impl VnishSensorDecl {
    /// `true` when the transcribed address is a plausible 7-bit I²C address
    /// (`<= 0x7F`). `0x98` passthrough pseudo-addresses return `false`.
    pub fn is_seven_bit_addr(&self) -> bool {
        self.i2c_addr <= 0x7F
    }
}

/// A `{default, min, max}` triple as VNish declares it. Purely declarative;
/// carries no unit by itself (the field name at the use site does).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeclaredRange<T> {
    pub default: T,
    pub min: T,
    pub max: T,
}

impl<T: PartialOrd + Copy> DeclaredRange<T> {
    /// `min <= default <= max` — the only shape a sane declared range has.
    pub fn is_ordered(&self) -> bool {
        self.min <= self.default && self.default <= self.max
    }
}

/// VNish's declared thermal thresholds for one model — **VNish's shipped
/// values, recorded as RE evidence. NOT DCENT safety policy**; nothing may
/// consume these as limits in a control path.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VnishThermalLimits {
    /// Chip temp at which VNish declares danger/shutdown (90 corpus-wide).
    pub danger_chip_c: i16,
    /// Chip temp VNish flags as hot (85 corpus-wide).
    pub hot_chip_c: i16,
    /// Board temp VNish declares dangerous (80 corpus-wide).
    pub danger_board_c: i16,
    /// Ambient/board temp above which VNish starts without preheat.
    pub normal_start_c: i16,
    /// Coldest declared start temp (-30 on 62 models, 0 on 15).
    pub min_start_c: i16,
    /// Offset VNish adds to the board-sensor reading to estimate chip
    /// junction temp. NOT universally 15: corpus census is 15/10/5/0.
    pub chip_temp_offset_c: i16,
}

/// A VNish cooling mode. Presence of `auto`/`manual` here is coherent with
/// the presence of the matching config block on the row (validated).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VnishCoolingMode {
    /// PID toward `auto_target_c`.
    Auto,
    /// Fixed duty within `manual_fan_pct`.
    Manual,
    /// No fans assumed (external water/oil loop).
    Immersion,
}

/// One VNish 1.2.7 model row, transcribed verbatim (minus the refused
/// columns — module docs). Absent source values are `None`, never a default.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VnishModelDescriptor {
    /// Bitmain model designator (registry key). Verbatim — includes the
    /// trailing-dash rev variants (`BHB56804-`) and the placeholder IDs
    /// (`42801`, `BHBXXXX`, `BHBXXXXX`, `HHBXXX`) exactly as VNish ships
    /// them.
    pub btm_model: String,
    /// Row provenance — always
    /// [`DescriptorProvenance::DeskVnishFirmwareExperimental`].
    pub provenance: DescriptorProvenance,
    /// Marketing name as VNish spells it (`"Antminer S19j Pro-A"`).
    pub marketing_name: String,
    /// VNish series bucket (`"l7"`, `"l9"`, `"x19"`, `"x21"`).
    pub series: String,
    /// VNish internal model code (`"s19jpro-a"`).
    pub model_code: String,
    /// Declared hashboard slots. NOTE: on the 14 SKUs shared with the ePIC
    /// registry's `chains_per_unit = 4` rows, VNish declares 3 — agreeing
    /// with DCENT live units. Conflict recorded in module docs; still desk
    /// data, still not a live board count.
    pub chains_per_unit: u8,
    /// ASICs on one hashboard chain (up to 216 — S21 Hydro).
    pub chips_per_chain: u16,
    /// ASICs per chain voltage domain (source column `cores_per_domain`,
    /// renamed: its arithmetic role is chips-per-domain and it matches the
    /// ePIC `chips_per_domain` on all 36 overlapping SKUs).
    pub chips_per_domain: u8,
    /// Voltage domains along the chain (source column `num_domains`).
    pub domains_per_chain: u8,
    /// VNish's declared access route for the whole sensor roster.
    pub sensor_access: VnishSensorAccess,
    /// Declared sensors, in source order (2..=8 across the corpus).
    pub sensors: Vec<VnishSensorDecl>,
    /// VNish's shipped thermal thresholds (RE evidence, not DCENT policy).
    pub limits: VnishThermalLimits,
    /// Declared cooling modes. Hydro/immersion models declare ONLY
    /// `immersion`.
    pub cooling_modes: Vec<VnishCoolingMode>,
    /// Auto-mode target temp range (°C). `None` on the 25 immersion-only
    /// models — genuinely absent in the source, never defaulted.
    pub auto_target_c: Option<DeclaredRange<i16>>,
    /// Manual fan duty range (%). `None` on the 25 immersion-only models.
    pub manual_fan_pct: Option<DeclaredRange<u8>>,
    /// Minimum-healthy-fan-count range. Independently absent on 15 models
    /// (all immersion-only, but 10 immersion-only models DO declare it —
    /// imported exactly as shipped).
    pub fan_min_count: Option<DeclaredRange<u8>>,
    /// Control-board platforms of the firmware images this model row was
    /// observed in (all 77 models appear in all four: aml/bb/cv/xil).
    pub observed_platforms: Vec<String>,
}

impl VnishModelDescriptor {
    /// Declared sensor count on ONE hashboard — the honest `expected` for
    /// coverage accounting against this corpus.
    pub fn expected_sensors_per_board(&self) -> u16 {
        self.sensors.len() as u16
    }

    /// Declared sensors across the whole unit, using the row's declared
    /// chain count. Desk arithmetic over desk data — not a live count.
    pub fn declared_sensors_per_unit(&self) -> u16 {
        self.expected_sensors_per_board()
            .saturating_mul(u16::from(self.chains_per_unit))
    }

    /// Declared ASICs across the whole unit (up to 3×216 = 648 and 4×180 =
    /// 720 in this corpus — hence the widened result type).
    pub fn declared_chips_per_unit(&self) -> u32 {
        u32::from(self.chips_per_chain) * u32::from(self.chains_per_unit)
    }

    /// `true` when the model declares ONLY immersion cooling (no fan
    /// curve, no auto target — the hydro/immersion class).
    pub fn is_immersion_only(&self) -> bool {
        self.cooling_modes == [VnishCoolingMode::Immersion]
    }

    /// Sensors at a given coarse location, source order preserved.
    pub fn sensors_at(
        &self,
        location: VnishSensorLocation,
    ) -> impl Iterator<Item = &VnishSensorDecl> {
        self.sensors.iter().filter(move |s| s.location == location)
    }

    /// An all-unknown per-board [`SensorSweep`] with this row's declared
    /// expectation — the bridge into the shared coverage accounting of
    /// [`crate::sensor_topology`]. Unknown is not 0 °C.
    pub fn empty_board_sweep(&self) -> SensorSweep {
        SensorSweep {
            hottest_c: None,
            covered: 0,
            expected: self.expected_sensors_per_board(),
        }
    }
}

/// Validation errors surfaced by [`validate_vnish_descriptor`]. With the
/// pinned generated corpus these are unreachable (test-pinned); the error
/// path exists so future data imports fail closed instead of guessing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VnishMatrixError {
    pub btm_model: String,
    pub detail: String,
}

impl std::fmt::Display for VnishMatrixError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.btm_model, self.detail)
    }
}

impl std::error::Error for VnishMatrixError {}

fn err(model: &str, detail: impl Into<String>) -> VnishMatrixError {
    VnishMatrixError {
        btm_model: model.to_string(),
        detail: detail.into(),
    }
}

/// Fail-closed structural validation of one row. Refuses (never repairs):
/// wrong provenance, empty sensor roster, broken domain arithmetic,
/// cooling-block/mode incoherence, unordered ranges, and inverted
/// thresholds.
pub fn validate_vnish_descriptor(d: &VnishModelDescriptor) -> Result<(), VnishMatrixError> {
    let m = d.btm_model.as_str();
    if d.provenance != DescriptorProvenance::DeskVnishFirmwareExperimental {
        return Err(err(m, "row must carry VNish desk provenance"));
    }
    if d.sensors.is_empty() {
        return Err(err(m, "sensor roster is empty"));
    }
    if d.chains_per_unit == 0 || d.chips_per_chain == 0 {
        return Err(err(m, "zero chains or chips"));
    }
    let domain_product = u16::from(d.chips_per_domain) * u16::from(d.domains_per_chain);
    if domain_product != d.chips_per_chain {
        return Err(err(
            m,
            format!(
                "domain arithmetic broken: {} x {} != {}",
                d.chips_per_domain, d.domains_per_chain, d.chips_per_chain
            ),
        ));
    }
    if d.cooling_modes.is_empty() {
        return Err(err(m, "no cooling modes declared"));
    }
    // Coherence: a cooling block exists iff its mode is declared.
    let has_auto_mode = d.cooling_modes.contains(&VnishCoolingMode::Auto);
    let has_manual_mode = d.cooling_modes.contains(&VnishCoolingMode::Manual);
    if has_auto_mode != d.auto_target_c.is_some() {
        return Err(err(m, "auto mode/config-block incoherence"));
    }
    if has_manual_mode != d.manual_fan_pct.is_some() {
        return Err(err(m, "manual mode/config-block incoherence"));
    }
    if let Some(r) = &d.auto_target_c {
        if !r.is_ordered() {
            return Err(err(m, "auto_target_c range not ordered"));
        }
    }
    if let Some(r) = &d.manual_fan_pct {
        if !r.is_ordered() {
            return Err(err(m, "manual_fan_pct range not ordered"));
        }
    }
    if let Some(r) = &d.fan_min_count {
        if !r.is_ordered() {
            return Err(err(m, "fan_min_count range not ordered"));
        }
    }
    let l = &d.limits;
    if l.hot_chip_c >= l.danger_chip_c {
        return Err(err(m, "hot_chip_c must be below danger_chip_c"));
    }
    if l.min_start_c > l.normal_start_c {
        return Err(err(m, "min_start_c above normal_start_c"));
    }
    if l.chip_temp_offset_c < 0 {
        return Err(err(m, "negative chip_temp_offset_c"));
    }
    if d.observed_platforms.is_empty() {
        return Err(err(m, "no observed platforms"));
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
struct MatrixFile {
    schema: String,
    source_csv: String,
    source_matrix_doc: String,
    roster_scope: String,
    firmware_images: Vec<String>,
    excluded_columns: Vec<String>,
    models: Vec<VnishModelDescriptor>,
}

struct VnishRegistry {
    models: Vec<VnishModelDescriptor>,
    by_model: HashMap<String, usize>,
}

fn vnish_registry() -> &'static VnishRegistry {
    static REGISTRY: OnceLock<VnishRegistry> = OnceLock::new();
    REGISTRY.get_or_init(|| {
        // Checked-in generated data, test-pinned: a parse/validate failure
        // here is a build-data defect, not a runtime condition (same posture
        // as `hashboard_topology::registry`).
        let file: MatrixFile = serde_json::from_str(MATRIX_JSON)
            .expect("vnish_thermal_matrix_1_2_7.json is checked-in generated data and must parse");
        assert_eq!(
            file.schema, "dcent-vnish-thermal-matrix-v1",
            "unexpected VNish matrix data schema"
        );
        assert_eq!(
            file.firmware_images.len(),
            18,
            "consensus contract is defined over 18 firmware images"
        );
        for d in &file.models {
            validate_vnish_descriptor(d)
                .expect("pinned VNish matrix corpus must pass fail-closed validation");
        }
        let by_model = file
            .models
            .iter()
            .enumerate()
            .map(|(i, d)| (d.btm_model.clone(), i))
            .collect();
        VnishRegistry {
            models: file.models,
            by_model,
        }
    })
}

/// All VNish matrix rows, sorted by `btm_model` (77 as of the 1.2.7 import).
pub fn all_vnish_models() -> &'static [VnishModelDescriptor] {
    &vnish_registry().models
}

/// Look up one row by exact Bitmain model designator (e.g. `"BHB42601"`,
/// `"HHB68501"`, or the rev-variant `"BHB56804-"`). Fail-closed: unknown
/// designators return `None`, never a nearest match.
pub fn vnish_model_by_btm(btm_model: &str) -> Option<&'static VnishModelDescriptor> {
    let reg = vnish_registry();
    reg.by_model.get(btm_model).map(|&i| &reg.models[i])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base_row() -> VnishModelDescriptor {
        vnish_model_by_btm("BHB42601").expect("pinned row").clone()
    }

    #[test]
    fn registry_parses_and_has_exactly_77_models() {
        assert_eq!(all_vnish_models().len(), 77);
        assert!(vnish_model_by_btm("NOT-A-MODEL").is_none());
    }

    #[test]
    fn every_row_passes_fail_closed_validation() {
        for d in all_vnish_models() {
            validate_vnish_descriptor(d).expect("pinned corpus row");
        }
    }

    #[test]
    fn validation_refuses_wrong_provenance() {
        let mut d = base_row();
        d.provenance = DescriptorProvenance::DeskJigDbExperimental;
        assert!(validate_vnish_descriptor(&d).is_err());
    }

    #[test]
    fn validation_refuses_broken_domain_arithmetic() {
        let mut d = base_row();
        d.chips_per_domain = 4; // 4 x 42 != 126
        assert!(validate_vnish_descriptor(&d).is_err());
    }

    #[test]
    fn validation_refuses_mode_block_incoherence() {
        // Declaring auto mode while dropping its config block = ambiguous
        // row = refused (and vice versa: a block without the mode).
        let mut d = base_row();
        d.auto_target_c = None;
        assert!(validate_vnish_descriptor(&d).is_err());

        let mut d = base_row();
        d.cooling_modes = vec![VnishCoolingMode::Immersion];
        // auto/manual blocks still present without their modes.
        assert!(validate_vnish_descriptor(&d).is_err());
    }

    #[test]
    fn validation_refuses_unordered_ranges_and_inverted_limits() {
        let mut d = base_row();
        d.manual_fan_pct = Some(DeclaredRange {
            default: 5,
            min: 10,
            max: 100,
        });
        assert!(validate_vnish_descriptor(&d).is_err());

        let mut d = base_row();
        d.limits.hot_chip_c = d.limits.danger_chip_c;
        assert!(validate_vnish_descriptor(&d).is_err());
    }

    #[test]
    fn validation_refuses_empty_sensor_roster() {
        let mut d = base_row();
        d.sensors.clear();
        assert!(validate_vnish_descriptor(&d).is_err());
    }

    #[test]
    fn serde_fails_closed_on_unknown_access_and_unknown_fields() {
        // `via_mixed` is in VNish's schema but observed on zero rows — it
        // must be REFUSED at deserialization, not silently accepted.
        assert!(serde_json::from_str::<VnishSensorAccess>("\"via_mixed\"").is_err());
        assert!(serde_json::from_str::<VnishSensorAccess>("\"via-pic\"").is_err());
        assert!(serde_json::from_str::<VnishSensorAccess>("\"via_pic\"").is_ok());
        // Unknown location labels fail closed too.
        assert!(serde_json::from_str::<VnishSensorLocation>("\"center\"").is_err());
        // Unknown fields on a sensor decl are refused (deny_unknown_fields).
        assert!(serde_json::from_str::<VnishSensorDecl>(
            r#"{"i2c_addr":72,"location":"front","extra":1}"#
        )
        .is_err());
    }

    #[test]
    fn unknown_is_absent_not_a_default() {
        // The 25 hydro/immersion rows genuinely ship without auto/manual
        // blocks — they must surface as None, never a fabricated curve.
        let d = vnish_model_by_btm("HHB56601").expect("S19 XP Hydro row");
        assert!(d.is_immersion_only());
        assert_eq!(d.auto_target_c, None);
        assert_eq!(d.manual_fan_pct, None);
        assert_eq!(d.fan_min_count, None);
        // ...while S21 Hydro (also immersion-only) DOES declare
        // fan_min_count — imported exactly as shipped, not "fixed".
        let d = vnish_model_by_btm("HHB68501").expect("S21 Hydro row");
        assert!(d.is_immersion_only());
        assert_eq!(
            d.fan_min_count,
            Some(DeclaredRange {
                default: 4,
                min: 1,
                max: 4
            })
        );
    }

    #[test]
    fn coverage_bridge_starts_all_unknown() {
        let d = vnish_model_by_btm("A3HB70501").expect("S21 XP row");
        let sweep = d.empty_board_sweep();
        assert_eq!(sweep.hottest_c, None);
        assert_eq!(sweep.covered, 0);
        assert_eq!(sweep.expected, 4);
        assert!(!sweep.is_complete());
        assert!(!sweep.known_cooler_than(1000.0));
    }

    #[test]
    fn passthrough_pseudo_addresses_are_flagged_not_normalized() {
        // S19a: all four sensors at the 0x98 passthrough pseudo-address.
        let d = vnish_model_by_btm("BHB28611").expect("S19a row");
        assert_eq!(d.sensor_access, VnishSensorAccess::ViaChipAuto);
        for s in &d.sensors {
            assert_eq!(s.i2c_addr, 0x98);
            assert!(!s.is_seven_bit_addr());
        }
    }
}
