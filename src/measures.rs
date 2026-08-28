//! The four `user.metrics` measurement types and how a raw Withings measure
//! becomes a number a person recognises.
//!
//! Withings encodes every measure as an integer `value` and a base-10
//! exponent `unit`, so a weight of 70.5 kg arrives as `{"value": 70500,
//! "unit": -3}`. Emitting `value` unscaled would be a confidently wrong number
//! rather than a missing one, which is the failure worth designing against.

use serde::Serialize;
use serde_json::Value;

/// A Withings `meastype` this server understands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MeasureType {
    /// Withings' `meastype` number.
    pub meastype: u16,
    /// Stable machine name, used as the key in tool output.
    pub name: &'static str,
    /// Unit the scaled value is expressed in.
    pub unit: &'static str,
    pub description: &'static str,
}

/// Every type this server reads. `scope=user.metrics` covers more than these
/// four; the catalogue is deliberately narrow because a tool that returns
/// blood pressure was not asked for.
pub const SUPPORTED: &[MeasureType] = &[
    MeasureType {
        meastype: 1,
        name: "weight",
        unit: "kg",
        description: "Body weight.",
    },
    MeasureType {
        meastype: 6,
        name: "body_fat_percentage",
        unit: "%",
        description: "Fat ratio as a percentage of body weight.",
    },
    MeasureType {
        meastype: 8,
        name: "fat_mass",
        unit: "kg",
        description: "Fat mass by weight.",
    },
    MeasureType {
        meastype: 76,
        name: "muscle_mass",
        unit: "kg",
        description: "Muscle mass by weight.",
    },
];

/// Look a supported type up by its Withings number.
#[must_use]
pub fn by_meastype(meastype: u16) -> Option<&'static MeasureType> {
    SUPPORTED.iter().find(|entry| entry.meastype == meastype)
}

/// Look a supported type up by its machine name.
#[must_use]
pub fn by_name(name: &str) -> Option<&'static MeasureType> {
    SUPPORTED.iter().find(|entry| entry.name == name)
}

/// Every supported `meastype`, in catalogue order.
#[must_use]
pub fn all_meastypes() -> Vec<u16> {
    SUPPORTED.iter().map(|entry| entry.meastype).collect()
}

/// One scaled measurement.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct Measurement {
    /// Withings' `meastype`.
    pub meastype: u16,
    /// Stable machine name, or `unknown` for a type outside the catalogue.
    pub name: &'static str,
    /// `value * 10^unit`, the number a person reads.
    pub value: f64,
    pub unit: &'static str,
    /// Unix seconds the measurement was taken.
    pub taken_at: i64,
    /// Withings group id, so a caller can tell two readings in one weigh-in
    /// from two weigh-ins.
    pub group_id: i64,
}

/// A measure Withings returned whose `meastype` is outside the catalogue.
const UNKNOWN: MeasureType = MeasureType {
    meastype: 0,
    name: "unknown",
    unit: "",
    description: "",
};

/// Scale one raw Withings measure.
///
/// `unit` is a base-10 exponent and is normally negative.
#[must_use]
pub fn scale(value: i64, unit: i32) -> f64 {
    #[allow(clippy::cast_precision_loss)]
    let value = value as f64;
    value * 10f64.powi(unit)
}

/// Flatten a `measure?action=getmeas` body into scaled measurements.
///
/// Unparseable groups and measures are skipped rather than failing the whole
/// read: one malformed entry in a year of history should not make the year
/// unreadable. Anything skipped is absent from the output rather than present
/// with a placeholder value.
#[must_use]
pub fn flatten(body: &Value) -> Vec<Measurement> {
    let Some(groups) = body.get("measuregrps").and_then(Value::as_array) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for group in groups {
        let group_id = group.get("grpid").and_then(Value::as_i64).unwrap_or(0);
        let taken_at = group.get("date").and_then(Value::as_i64).unwrap_or(0);
        let Some(measures) = group.get("measures").and_then(Value::as_array) else {
            continue;
        };
        for measure in measures {
            let (Some(value), Some(unit), Some(meastype)) = (
                measure.get("value").and_then(Value::as_i64),
                measure.get("unit").and_then(Value::as_i64),
                measure.get("type").and_then(Value::as_i64),
            ) else {
                continue;
            };
            let Ok(meastype) = u16::try_from(meastype) else {
                continue;
            };
            let Ok(unit) = i32::try_from(unit) else {
                continue;
            };
            let kind = by_meastype(meastype).unwrap_or(&UNKNOWN);
            out.push(Measurement {
                meastype,
                name: kind.name,
                value: scale(value, unit),
                unit: kind.unit,
                taken_at,
                group_id,
            });
        }
    }
    out
}

/// The most recent measurement of each supported type.
///
/// A type with no reading in the window is absent from the result rather than
/// present with a zero, so a caller cannot mistake "never measured" for
/// "measured as nothing".
#[must_use]
pub fn latest_per_type(measurements: &[Measurement]) -> Vec<Measurement> {
    let mut latest: Vec<Measurement> = Vec::new();
    for measurement in measurements {
        match latest
            .iter_mut()
            .find(|held| held.meastype == measurement.meastype)
        {
            Some(held) if held.taken_at < measurement.taken_at => *held = measurement.clone(),
            Some(_) => {}
            None => latest.push(measurement.clone()),
        }
    }
    latest.sort_by_key(|measurement| measurement.meastype);
    latest
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use serde_json::json;

    use super::*;

    /// A `getmeas` body in the shape Withings' documentation describes. It is
    /// invented data: this repository carries no real measurement of anyone.
    fn fixture() -> Value {
        json!({
            "updatetime": 1_724_900_000_i64,
            "timezone": "Asia/Singapore",
            "measuregrps": [
                {
                    "grpid": 2,
                    "attrib": 0,
                    "date": 1_724_800_000_i64,
                    "created": 1_724_800_010_i64,
                    "category": 1,
                    "deviceid": "device",
                    "measures": [
                        {"value": 70_500, "type": 1, "unit": -3},
                        {"value": 1_820, "type": 6, "unit": -2},
                        {"value": 12_820, "type": 8, "unit": -3},
                        {"value": 54_100, "type": 76, "unit": -3}
                    ]
                },
                {
                    "grpid": 1,
                    "attrib": 0,
                    "date": 1_724_700_000_i64,
                    "category": 1,
                    "measures": [
                        {"value": 71_000, "type": 1, "unit": -3},
                        {"value": 1_236, "type": 91, "unit": -1}
                    ]
                }
            ]
        })
    }

    #[test]
    fn a_raw_measure_is_scaled_by_its_exponent() {
        assert!((scale(70_500, -3) - 70.5).abs() < 1e-9);
        assert!((scale(1_820, -2) - 18.2).abs() < 1e-9);
        // A positive exponent is legal and rare; getting the sign wrong is the
        // failure this pins.
        assert!((scale(7, 1) - 70.0).abs() < 1e-9);
        assert!((scale(0, -3) - 0.0).abs() < 1e-9);
    }

    #[test]
    fn flatten_scales_every_measure_and_keeps_its_group() {
        let flat = flatten(&fixture());
        assert_eq!(flat.len(), 6);
        let weight = flat.iter().find(|m| m.name == "weight").unwrap();
        assert!((weight.value - 70.5).abs() < 1e-9);
        assert_eq!(weight.unit, "kg");
        assert_eq!(weight.group_id, 2);
        assert_eq!(weight.taken_at, 1_724_800_000);
        let ratio = flat
            .iter()
            .find(|m| m.name == "body_fat_percentage")
            .unwrap();
        assert!((ratio.value - 18.2).abs() < 1e-9);
        assert_eq!(ratio.unit, "%");
    }

    #[test]
    fn a_meastype_outside_the_catalogue_is_named_rather_than_dropped() {
        // Pulse wave velocity, meastype 91, is in scope but not in the
        // catalogue. Dropping it silently would make the tool's output
        // disagree with the account.
        let flat = flatten(&fixture());
        let unknown = flat.iter().find(|m| m.meastype == 91).unwrap();
        assert_eq!(unknown.name, "unknown");
        assert_eq!(unknown.unit, "");
    }

    #[test]
    fn a_malformed_measure_is_skipped_and_the_rest_survive() {
        let body = json!({"measuregrps": [{
            "grpid": 1,
            "date": 10,
            "measures": [
                {"value": "seventy", "type": 1, "unit": -3},
                {"type": 1, "unit": -3},
                {"value": 70_500, "type": 1, "unit": -3}
            ]
        }]});
        let flat = flatten(&body);
        assert_eq!(flat.len(), 1);
        assert!((flat[0].value - 70.5).abs() < 1e-9);
    }

    #[test]
    fn a_body_with_no_groups_is_empty_rather_than_an_error() {
        assert!(flatten(&json!({"measuregrps": []})).is_empty());
        assert!(flatten(&json!({})).is_empty());
        assert!(flatten(&Value::Null).is_empty());
    }

    #[test]
    fn latest_per_type_takes_the_newest_reading_of_each() {
        let latest = latest_per_type(&flatten(&fixture()));
        // Four supported types plus the uncatalogued 91.
        assert_eq!(latest.len(), 5);
        let weight = latest.iter().find(|m| m.name == "weight").unwrap();
        // 70.5 is from grpid 2 at the later date; 71.0 is the older reading.
        assert!((weight.value - 70.5).abs() < 1e-9);
        assert_eq!(weight.taken_at, 1_724_800_000);
        assert!(latest.windows(2).all(|w| w[0].meastype <= w[1].meastype));
    }

    #[test]
    fn a_type_with_no_reading_is_absent_rather_than_zero() {
        let body = json!({"measuregrps": [{
            "grpid": 1, "date": 10, "measures": [{"value": 70_500, "type": 1, "unit": -3}]
        }]});
        let latest = latest_per_type(&flatten(&body));
        assert_eq!(latest.len(), 1);
        assert!(latest.iter().all(|m| m.name != "muscle_mass"));
    }

    #[test]
    fn the_catalogue_is_the_four_types_the_scope_was_granted_for() {
        assert_eq!(all_meastypes(), vec![1, 6, 8, 76]);
        assert_eq!(by_name("weight").unwrap().meastype, 1);
        assert_eq!(by_meastype(76).unwrap().name, "muscle_mass");
        assert!(by_name("blood_pressure").is_none());
        assert!(by_meastype(9).is_none());
        // Names are the keys a consumer writes against, so a rename is a
        // breaking change and this is where it shows up.
        let names: Vec<&str> = SUPPORTED.iter().map(|entry| entry.name).collect();
        assert_eq!(
            names,
            ["weight", "body_fat_percentage", "fat_mass", "muscle_mass"]
        );
    }
}
