//! Gnark constraint-system (`*.ccs`) parser
use std::path::Path;

use super::decode_intcomp::IntcompWord;
use crate::{
    R1CS,
    types::{
        Blueprint, Body, CommitmentInfo, Groth16Commitment, IntWidth, Levels, MetaData,
        PackedInstruction, PlonkCommitment, SectionHeader, SystemType,
    },
};
use ark_bn254::Fr;
use ark_ff::{BigInt, Fp};
use byteorder::{LittleEndian, ReadBytesExt};

use super::ParseError;

impl R1CS {
    /// Loads a portable-format CCS from disk.
    #[cfg(not(target_arch = "wasm32"))]
    pub fn load(path: impl AsRef<Path>) -> Result<Self, ParseError> {
        let bytes = std::fs::read(path)?;
        Self::from_bytes(&bytes)
    }

    /// Parses a CCS from raw bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ParseError> {
        const WRAPPER_LEN: usize = 4 * 8;
        if bytes.len() < WRAPPER_LEN {
            return Err(ParseError::Ccs(format!(
                "file too short for wrapper: {} bytes, need {WRAPPER_LEN}",
                bytes.len()
            )));
        }

        let mut r = bytes;
        let wrapper = MetaData {
            total_len: r.read_u64::<LittleEndian>()?,
            gnark_major: r.read_u64::<LittleEndian>()?,
            gnark_minor: r.read_u64::<LittleEndian>()?,
            gnark_patch: r.read_u64::<LittleEndian>()?,
        };

        let total_len = u64_to_u32(wrapper.total_len, "total_len")? as usize;
        let payload_end = WRAPPER_LEN
            .checked_add(total_len)
            .ok_or_else(|| ParseError::Ccs("total_len overflow".into()))?;

        if bytes.len() < payload_end {
            return Err(ParseError::Ccs(format!(
                "truncated: wrapper claims {} payload bytes, file has {}",
                wrapper.total_len,
                bytes.len() - WRAPPER_LEN
            )));
        }
        let payload = &bytes[WRAPPER_LEN..payload_end];

        if payload.len() < 32 {
            return Err(ParseError::Ccs(
                "payload too short for section header".into(),
            ));
        }
        let mut sr = payload;
        let section_header = SectionHeader {
            levels_len: sr.read_u64::<LittleEndian>()?,
            instructions_len: sr.read_u64::<LittleEndian>()?,
            calldata_len: sr.read_u64::<LittleEndian>()?,
            body_len: sr.read_u64::<LittleEndian>()?,
        };

        let mut off = 32usize;
        let levels = take_section(payload, &mut off, section_header.levels_len, parse_levels)?;
        let instructions = take_section(
            payload,
            &mut off,
            section_header.instructions_len,
            parse_instructions,
        )?;
        let calldata = take_section(
            payload,
            &mut off,
            section_header.calldata_len,
            parse_calldata,
        )?;
        let body = take_section(payload, &mut off, section_header.body_len, parse_body)?;
        let coefficients = parse_coeff_table(&payload[off..])?;

        Ok(Self {
            metadata: wrapper,
            section_header,
            levels,
            instructions,
            calldata,
            body,
            coefficients,
        })
    }
}

fn take_section<T>(
    payload: &[u8],
    off: &mut usize,
    len: u64,
    parse: impl FnOnce(&[u8]) -> Result<T, ParseError>,
) -> Result<T, ParseError> {
    let bytes = take_raw(payload, off, len)?;
    parse(bytes)
}

fn take_raw<'a>(payload: &'a [u8], off: &mut usize, len: u64) -> Result<&'a [u8], ParseError> {
    let len = u64_to_u32(len, "section length")? as usize;
    let end = off
        .checked_add(len)
        .ok_or_else(|| ParseError::Ccs("section length overflow".into()))?;
    if end > payload.len() {
        return Err(ParseError::Ccs(format!(
            "section runs past payload: need {end} bytes, have {}",
            payload.len()
        )));
    }
    let slice = &payload[*off..end];
    *off = end;
    Ok(slice)
}

fn parse_levels(mut r: &[u8]) -> Result<Levels, ParseError> {
    let n_levels = u64_to_u32(r.read_u64::<LittleEndian>()?, "n_levels")? as usize;
    let mut data: Vec<u32> = Vec::new();
    let mut offsets: Vec<u32> = Vec::with_capacity(n_levels + 1);
    offsets.push(0);
    for _ in 0..n_levels {
        read_intcomp_block_into::<u32>(&mut r, &mut data)?;
        offsets.push(u64_to_u32(data.len() as u64, "levels total length")?);
    }
    if !r.is_empty() {
        return Err(ParseError::Ccs(format!(
            "{} trailing bytes in levels section",
            r.len()
        )));
    }
    Ok(Levels { data, offsets })
}

fn parse_instructions(mut r: &[u8]) -> Result<Vec<PackedInstruction>, ParseError> {
    let bp = read_intcomp_block::<u32>(&mut r)?;
    let co = read_intcomp_block::<u32>(&mut r)?;
    let wo = read_intcomp_block::<u32>(&mut r)?;
    let sc = read_intcomp_block::<u64>(&mut r)?;
    if bp.len() != co.len() || co.len() != wo.len() || wo.len() != sc.len() {
        return Err(ParseError::Ccs(format!(
            "instruction column length mismatch: bp={} co={} wo={} sc={}",
            bp.len(),
            co.len(),
            wo.len(),
            sc.len()
        )));
    }
    if !r.is_empty() {
        return Err(ParseError::Ccs(format!(
            "{} trailing bytes in instructions section",
            r.len()
        )));
    }
    let mut out = Vec::with_capacity(bp.len());
    for (((bp, co), wo), sc) in bp.into_iter().zip(co).zip(wo).zip(sc) {
        out.push(PackedInstruction {
            blueprint_id: bp,
            constraint_offset: co,
            wire_offset: wo,
            start_call_data: sc,
        });
    }
    Ok(out)
}

/// Reads one `(n_words u64, n_words × T-LE = intcomp(values))` chunk — the
/// wire shape gnark's `CompressAndWriteUints{32,64}` produces — and returns
/// the decoded values as a fresh `Vec<T>`. Thin wrapper around
/// [`read_intcomp_block_into`].
fn read_intcomp_block<T: IntcompWord>(r: &mut &[u8]) -> Result<Vec<T>, ParseError> {
    let mut out = Vec::new();
    read_intcomp_block_into(r, &mut out)?;
    Ok(out)
}

/// Appending form of [`read_intcomp_block`]: decodes into the caller's `Vec`
/// without an intermediate allocation. Useful when many blocks accumulate
/// into one buffer (see [`parse_levels`]).
fn read_intcomp_block_into<T: IntcompWord>(
    r: &mut &[u8],
    out: &mut Vec<T>,
) -> Result<(), ParseError> {
    let n_words = u64_to_u32(r.read_u64::<LittleEndian>()?, "intcomp n_words")? as usize;
    // u32 * 8 fits in u64, so no overflow check needed; bound against payload below.
    let bytes_needed = (n_words as u64) * (T::SIZE as u64);
    if (r.len() as u64) < bytes_needed {
        return Err(ParseError::Ccs(format!(
            "intcomp block truncated: need {bytes_needed} bytes, have {}",
            r.len()
        )));
    }
    let bytes_needed = bytes_needed as usize;
    let mut words = Vec::with_capacity(n_words);
    for i in 0..n_words {
        words.push(T::read_le(&r[i * T::SIZE..]));
    }
    *r = &r[bytes_needed..];
    T::uncompress(&words, out);
    Ok(())
}

fn parse_calldata(mut r: &[u8]) -> Result<Vec<u32>, ParseError> {
    let n = u64_to_u32(r.read_u64::<LittleEndian>()?, "calldata n")? as usize;
    let mut out = Vec::with_capacity(n);
    for _ in 0..n {
        let v = read_uvarint(&mut r)?;
        out.push(v as u32);
    }
    if !r.is_empty() {
        return Err(ParseError::Ccs(format!(
            "{} trailing bytes in calldata section",
            r.len()
        )));
    }
    Ok(out)
}

// ----- body decoder (CBOR with custom tag set) -----

fn parse_body(bytes: &[u8]) -> Result<Body, ParseError> {
    let value: ciborium::Value = ciborium::from_reader(bytes)
        .map_err(|e| ParseError::Ccs(format!("body: cbor decode: {e}")))?;

    let map = as_map(&value, "body")?;

    let gnark_version = take_str(map, "GnarkVersion")?.to_owned();
    let scalar_field = take_str(map, "ScalarField")?.to_owned();
    let nb_constraints = take_u64(map, "NbConstraints")?;
    let nb_internal_variables = take_u64(map, "NbInternalVariables")?;
    let system_type = match take_u64(map, "Type")? {
        0 => SystemType::Unknown,
        1 => SystemType::R1cs,
        2 => SystemType::SparseR1cs,
        n => return Err(ParseError::Ccs(format!("body: unknown SystemType {n}"))),
    };
    let public = take_string_array(map, "Public")?;
    let secret = take_string_array(map, "Secret")?;
    let blueprints = parse_blueprints(get_field(map, "Blueprints")?)?;
    let commitment_info = parse_commitment_info(get_field(map, "CommitmentInfo")?)?;

    // Diagnostic-only fields — sanity-check the shape but don't surface the
    // values (the prover never reads them).
    expect_null_or_empty_map(map, "Logs")?;
    expect_null_or_empty_map(map, "DebugInfo")?;
    expect_empty_map(map, "MDebug")?;
    expect_empty_map(map, "MHintsDependencies")?;
    if let Some(st) = lookup_field(map, "SymbolTable") {
        let st_map = as_map(st, "SymbolTable")?;
        expect_null_or_empty_array(st_map, "Functions")?;
        expect_null_or_empty_array(st_map, "Locations")?;
    }
    // `GkrInfo` is always present in upstream output as a default-zero
    // `gkrinfo.StoringInfo` struct, populated or not. Whether GKR is actually
    // in use is determined by the absence of any GKR blueprint tag in
    // `Blueprints` — nothing here cares about the body's value, so it's
    // discarded.

    Ok(Body {
        gnark_version,
        scalar_field,
        system_type,
        blueprints,
        nb_constraints,
        nb_internal_variables,
        public,
        secret,
        commitment_info,
    })
}

fn parse_blueprints(value: &ciborium::Value) -> Result<Vec<Blueprint>, ParseError> {
    let arr = as_array(value, "Blueprints")?;
    arr.iter().map(parse_blueprint).collect()
}

type WidthPairedUnitBlueprint = (u64, u64, fn(IntWidth) -> Blueprint);

/// Each entry pairs the `(u32, u64)` tag forms of a width-parameterised unit
/// blueprint with its `Blueprint` constructor. Enum-variant tuple constructors
/// coerce to `fn(IntWidth) -> Blueprint`, so the table doubles as both lookup
/// and factory.
const WIDTH_PAIRED_UNIT_BLUEPRINTS: &[WidthPairedUnitBlueprint] = &[
    (
        TAG_GENERIC_SPARSE_R1C_U32,
        TAG_GENERIC_SPARSE_R1C_U64,
        Blueprint::GenericSparseR1c,
    ),
    (
        TAG_SPARSE_R1C_ADD_U32,
        TAG_SPARSE_R1C_ADD_U64,
        Blueprint::SparseR1cAdd,
    ),
    (
        TAG_SPARSE_R1C_MUL_U32,
        TAG_SPARSE_R1C_MUL_U64,
        Blueprint::SparseR1cMul,
    ),
    (
        TAG_SPARSE_R1C_BOOL_U32,
        TAG_SPARSE_R1C_BOOL_U64,
        Blueprint::SparseR1cBool,
    ),
    (
        TAG_BATCH_INVERSE_U32,
        TAG_BATCH_INVERSE_U64,
        Blueprint::BatchInverse,
    ),
];

fn parse_blueprint(value: &ciborium::Value) -> Result<Blueprint, ParseError> {
    let (tag, inner) = as_tag(value, "Blueprints[i]")?;
    match tag {
        TAG_GENERIC_HINT => {
            expect_empty_map_value(inner, "BlueprintGenericHint")?;
            Ok(Blueprint::GenericHint)
        }
        TAG_GENERIC_R1C => {
            expect_empty_map_value(inner, "BlueprintGenericR1C")?;
            Ok(Blueprint::GenericR1c)
        }
        TAG_LOOKUP_HINT_U32 => parse_lookup_hint(inner, IntWidth::U32),
        TAG_LOOKUP_HINT_U64 => parse_lookup_hint(inner, IntWidth::U64),
        _ => {
            for &(u32_tag, u64_tag, ctor) in WIDTH_PAIRED_UNIT_BLUEPRINTS {
                let width = if tag == u32_tag {
                    IntWidth::U32
                } else if tag == u64_tag {
                    IntWidth::U64
                } else {
                    continue;
                };
                expect_empty_map_value(inner, "Blueprint")?;
                return Ok(ctor(width));
            }
            Err(ParseError::Ccs(format!(
                "Blueprints[i]: unexpected tag {tag}"
            )))
        }
    }
}

fn parse_lookup_hint(value: &ciborium::Value, width: IntWidth) -> Result<Blueprint, ParseError> {
    let map = as_map(value, "BlueprintLookupHint")?;
    let entries = get_field(map, "EntriesCalldata")?;
    let arr = as_array(entries, "EntriesCalldata")?;
    let mut entries_calldata = Vec::with_capacity(arr.len());
    for v in arr {
        entries_calldata.push(value_to_u64(v, "EntriesCalldata[i]")? as u32);
    }
    Ok(Blueprint::LookupHint {
        width,
        entries_calldata,
    })
}

fn parse_commitment_info(value: &ciborium::Value) -> Result<CommitmentInfo, ParseError> {
    let (tag, inner) = as_tag(value, "CommitmentInfo")?;
    match tag {
        TAG_GROTH16_COMMITMENTS => {
            let arr = as_array_or_empty_seq(inner, "Groth16Commitments")?;
            let mut out = Vec::with_capacity(arr.len());
            for v in arr {
                out.push(parse_groth16_commitment(v)?);
            }
            Ok(CommitmentInfo::Groth16(out))
        }
        TAG_PLONK_COMMITMENTS => {
            let arr = as_array_or_empty_seq(inner, "PlonkCommitments")?;
            let mut out = Vec::with_capacity(arr.len());
            for v in arr {
                out.push(parse_plonk_commitment(v)?);
            }
            Ok(CommitmentInfo::Plonk(out))
        }
        other => Err(ParseError::Ccs(format!(
            "CommitmentInfo: unexpected tag {other}"
        ))),
    }
}

fn parse_groth16_commitment(value: &ciborium::Value) -> Result<Groth16Commitment, ParseError> {
    let map = as_map(value, "Groth16Commitment")?;
    Ok(Groth16Commitment {
        public_and_commitment_committed: take_int_array(map, "PublicAndCommitmentCommitted")?,
        private_committed: take_int_array(map, "PrivateCommitted")?,
        commitment_index: take_i64(map, "CommitmentIndex")?,
        nb_public_committed: take_i64(map, "NbPublicCommitted")?,
    })
}

fn parse_plonk_commitment(value: &ciborium::Value) -> Result<PlonkCommitment, ParseError> {
    let map = as_map(value, "PlonkCommitment")?;
    Ok(PlonkCommitment {
        committed: take_int_array(map, "Committed")?,
        commitment_index: take_i64(map, "CommitmentIndex")?,
        width: take_i64(map, "Width")?,
    })
}

// ----- ciborium::Value helpers -----

type CborMap = [(ciborium::Value, ciborium::Value)];

fn lookup_field<'a>(map: &'a CborMap, key: &str) -> Option<&'a ciborium::Value> {
    map.iter()
        .find(|(k, _)| matches!(k, ciborium::Value::Text(t) if t == key))
        .map(|(_, v)| v)
}

fn get_field<'a>(map: &'a CborMap, key: &str) -> Result<&'a ciborium::Value, ParseError> {
    lookup_field(map, key).ok_or_else(|| ParseError::Ccs(format!("body: missing field {key}")))
}

fn as_map<'a>(value: &'a ciborium::Value, ctx: &str) -> Result<&'a CborMap, ParseError> {
    match value {
        ciborium::Value::Map(m) => Ok(m.as_slice()),
        other => Err(ParseError::Ccs(format!(
            "{ctx}: expected map, got {}",
            describe(other)
        ))),
    }
}

fn as_array<'a>(
    value: &'a ciborium::Value,
    ctx: &str,
) -> Result<&'a [ciborium::Value], ParseError> {
    match value {
        ciborium::Value::Array(a) => Ok(a.as_slice()),
        other => Err(ParseError::Ccs(format!(
            "{ctx}: expected array, got {}",
            describe(other)
        ))),
    }
}

/// fxamacker/cbor encodes an empty Go slice as `null` rather than `[]`. Treat
/// either as an empty array for the commitment payload.
fn as_array_or_empty_seq<'a>(
    value: &'a ciborium::Value,
    ctx: &str,
) -> Result<&'a [ciborium::Value], ParseError> {
    match value {
        ciborium::Value::Array(a) => Ok(a.as_slice()),
        ciborium::Value::Null => Ok(&[]),
        other => Err(ParseError::Ccs(format!(
            "{ctx}: expected array or null, got {}",
            describe(other)
        ))),
    }
}

fn as_tag<'a>(
    value: &'a ciborium::Value,
    ctx: &str,
) -> Result<(u64, &'a ciborium::Value), ParseError> {
    match value {
        ciborium::Value::Tag(t, inner) => Ok((*t, inner.as_ref())),
        other => Err(ParseError::Ccs(format!(
            "{ctx}: expected CBOR tag, got {}",
            describe(other)
        ))),
    }
}

fn take_str<'a>(map: &'a CborMap, key: &str) -> Result<&'a str, ParseError> {
    match get_field(map, key)? {
        ciborium::Value::Text(s) => Ok(s.as_str()),
        other => Err(ParseError::Ccs(format!(
            "{key}: expected string, got {}",
            describe(other)
        ))),
    }
}

fn take_u64(map: &CborMap, key: &str) -> Result<u64, ParseError> {
    value_to_u64(get_field(map, key)?, key)
}

fn take_i64(map: &CborMap, key: &str) -> Result<i64, ParseError> {
    value_to_i64(get_field(map, key)?, key)
}

fn value_to_u64(value: &ciborium::Value, ctx: &str) -> Result<u64, ParseError> {
    match value {
        ciborium::Value::Integer(i) => u64::try_from(*i)
            .map_err(|_| ParseError::Ccs(format!("{ctx}: integer doesn't fit in u64"))),
        other => Err(ParseError::Ccs(format!(
            "{ctx}: expected integer, got {}",
            describe(other)
        ))),
    }
}

fn value_to_i64(value: &ciborium::Value, ctx: &str) -> Result<i64, ParseError> {
    match value {
        ciborium::Value::Integer(i) => i64::try_from(*i)
            .map_err(|_| ParseError::Ccs(format!("{ctx}: integer doesn't fit in i64"))),
        other => Err(ParseError::Ccs(format!(
            "{ctx}: expected integer, got {}",
            describe(other)
        ))),
    }
}

fn take_string_array(map: &CborMap, key: &str) -> Result<Vec<String>, ParseError> {
    let arr = as_array(get_field(map, key)?, key)?;
    arr.iter()
        .map(|v| match v {
            ciborium::Value::Text(s) => Ok(s.clone()),
            other => Err(ParseError::Ccs(format!(
                "{key}[i]: expected string, got {}",
                describe(other)
            ))),
        })
        .collect()
}

fn take_int_array(map: &CborMap, key: &str) -> Result<Vec<i64>, ParseError> {
    let arr = as_array_or_empty_seq(get_field(map, key)?, key)?;
    arr.iter().map(|v| value_to_i64(v, key)).collect()
}

fn expect_empty_map(map: &CborMap, key: &str) -> Result<(), ParseError> {
    if let Some(v) = lookup_field(map, key) {
        expect_empty_map_value(v, key)?;
    }
    Ok(())
}

fn expect_empty_map_value(value: &ciborium::Value, ctx: &str) -> Result<(), ParseError> {
    match value {
        ciborium::Value::Map(m) if m.is_empty() => Ok(()),
        other => Err(ParseError::Ccs(format!(
            "{ctx}: expected empty map, got {}",
            describe(other)
        ))),
    }
}

fn expect_null_or_empty_map(map: &CborMap, key: &str) -> Result<(), ParseError> {
    let Some(v) = lookup_field(map, key) else {
        return Ok(());
    };
    if is_null(v) || is_empty_map(v) {
        Ok(())
    } else {
        Err(ParseError::Ccs(format!(
            "{key}: expected null or empty map, got {}",
            describe(v)
        )))
    }
}

fn expect_null_or_empty_array(map: &CborMap, key: &str) -> Result<(), ParseError> {
    let Some(v) = lookup_field(map, key) else {
        return Ok(());
    };
    match v {
        ciborium::Value::Null => Ok(()),
        ciborium::Value::Array(a) if a.is_empty() => Ok(()),
        other => Err(ParseError::Ccs(format!(
            "{key}: expected null or empty array, got {}",
            describe(other)
        ))),
    }
}

fn is_null(value: &ciborium::Value) -> bool {
    matches!(value, ciborium::Value::Null)
}

fn is_empty_map(value: &ciborium::Value) -> bool {
    matches!(value, ciborium::Value::Map(m) if m.is_empty())
}

fn describe(value: &ciborium::Value) -> &'static str {
    match value {
        ciborium::Value::Null => "null",
        ciborium::Value::Bool(_) => "bool",
        ciborium::Value::Integer(_) => "integer",
        ciborium::Value::Float(_) => "float",
        ciborium::Value::Bytes(_) => "bytes",
        ciborium::Value::Text(_) => "text",
        ciborium::Value::Array(_) => "array",
        ciborium::Value::Map(_) => "map",
        ciborium::Value::Tag(_, _) => "tag",
        _ => "unknown",
    }
}

fn parse_coeff_table(mut r: &[u8]) -> Result<Vec<Fr>, ParseError> {
    if r.is_empty() {
        return Ok(Vec::new());
    }
    let n = u64_to_u32(r.read_u64::<LittleEndian>()?, "coeff table n")? as usize;
    let bytes_needed = (n as u64) * 32;
    if (r.len() as u64) < bytes_needed {
        return Err(ParseError::Ccs(format!(
            "coeff table truncated: need {bytes_needed} bytes, have {}",
            r.len()
        )));
    }
    let mut out = Vec::with_capacity(n);
    for _ in 0..n {
        let mut limbs = [0u64; 4];
        for limb in &mut limbs {
            *limb = r.read_u64::<LittleEndian>()?;
        }
        // gnark stores `fr.Element` in Montgomery form (R = 2^256 mod p);
        // ark-bn254 uses the same R, so the limbs are reused in place.
        out.push(Fp::new_unchecked(BigInt::new(limbs)));
    }
    if !r.is_empty() {
        return Err(ParseError::Ccs(format!(
            "{} trailing bytes after coeff table",
            r.len()
        )));
    }
    Ok(out)
}

/// Unsigned LEB128, matching Go's `binary.Uvarint`. Caps at 10 continuation
/// bytes (max u64) to keep a malformed stream from spinning indefinitely.
fn read_uvarint(r: &mut &[u8]) -> Result<u64, ParseError> {
    let mut value: u64 = 0;
    let mut shift: u32 = 0;
    for i in 0..10 {
        let b = r.read_u8()?;
        if b < 0x80 {
            if i == 9 && b > 1 {
                return Err(ParseError::Ccs("uvarint overflows u64".into()));
            }
            value |= (b as u64) << shift;
            return Ok(value);
        }
        value |= ((b & 0x7f) as u64) << shift;
        shift += 7;
    }
    Err(ParseError::Ccs(
        "uvarint missing terminator after 10 bytes".into(),
    ))
}

/// Bounds a wire-format `u64` length/count to `u32`, the natural width on
/// every target's `usize`. CCS files larger than 4 GiB aren't realistic
/// (browser WASM caps linear memory there anyway), so this is a portable
/// stand-in for `as usize` that errors instead of truncating on wasm32.
fn u64_to_u32(n: u64, ctx: &str) -> Result<u32, ParseError> {
    u32::try_from(n).map_err(|_| ParseError::Ccs(format!("{ctx}: {n} exceeds u32::MAX")))
}

// ----- CBOR tag numbers (mirror gnark's getTagSet, with the fork's additions) -----

const TAG_GENERIC_HINT: u64 = 5309735;
const TAG_GENERIC_R1C: u64 = 5309736;
const TAG_GROTH16_COMMITMENTS: u64 = 5309737;
const TAG_PLONK_COMMITMENTS: u64 = 5309738;
const TAG_GENERIC_SPARSE_R1C_U32: u64 = 5309739;
const TAG_SPARSE_R1C_ADD_U32: u64 = 5309740;
const TAG_SPARSE_R1C_MUL_U32: u64 = 5309741;
const TAG_SPARSE_R1C_BOOL_U32: u64 = 5309742;
const TAG_LOOKUP_HINT_U32: u64 = 5309743;
const TAG_GENERIC_SPARSE_R1C_U64: u64 = 5309744;
const TAG_SPARSE_R1C_ADD_U64: u64 = 5309745;
const TAG_SPARSE_R1C_MUL_U64: u64 = 5309746;
const TAG_SPARSE_R1C_BOOL_U64: u64 = 5309747;
const TAG_LOOKUP_HINT_U64: u64 = 5309748;
const TAG_BATCH_INVERSE_U32: u64 = 5309749;
const TAG_BATCH_INVERSE_U64: u64 = 5309750;
