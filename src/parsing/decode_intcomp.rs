//! Rust port of `UncompressUint32` / `UncompressUint64` from
//! <https://github.com/ronanh/intcomp>.

pub const BIT_PACKING_BLOCK_SIZE_32: usize = 128;
pub const BIT_PACKING_BLOCK_SIZE_64: usize = 256;

const GROUP_SIZE_32: usize = BIT_PACKING_BLOCK_SIZE_32 / 4; // 32
const GROUP_SIZE_64: usize = BIT_PACKING_BLOCK_SIZE_64 / 4; // 64

pub(super) trait IntcompWord: Sized {
    const SIZE: usize;
    fn read_le(bytes: &[u8]) -> Self;
    fn uncompress(input: &[Self], out: &mut Vec<Self>);
}

impl IntcompWord for u32 {
    const SIZE: usize = 4;
    fn read_le(b: &[u8]) -> Self {
        u32::from_le_bytes(b[..4].try_into().unwrap())
    }
    fn uncompress(input: &[Self], out: &mut Vec<Self>) {
        uncompress_uint32(input, out);
    }
}

impl IntcompWord for u64 {
    const SIZE: usize = 8;
    fn read_le(b: &[u8]) -> Self {
        u64::from_le_bytes(b[..8].try_into().unwrap())
    }
    fn uncompress(input: &[Self], out: &mut Vec<Self>) {
        uncompress_uint64(input, out);
    }
}

// ---------------------------------------------------------------------------
// Public API (specialised path)
// ---------------------------------------------------------------------------

pub fn uncompress_uint32(input: &[u32], out: &mut Vec<u32>) {
    if input.is_empty() {
        return;
    }
    let mut remaining = &input[..input.len() - 1];
    while !remaining.is_empty() {
        let uncompressed_size = remaining[0] as usize;
        remaining = if uncompressed_size < BIT_PACKING_BLOCK_SIZE_32 {
            uncompress_delta_var_byte_u32(remaining, out)
        } else {
            uncompress_delta_bin_pack_u32(remaining, out)
        };
    }
}

pub fn uncompress_uint64(input: &[u64], out: &mut Vec<u64>) {
    if input.is_empty() {
        return;
    }
    let mut remaining = &input[..input.len() - 1];
    while !remaining.is_empty() {
        let uncompressed_size = (remaining[0] as u32) as usize;
        remaining = if uncompressed_size < BIT_PACKING_BLOCK_SIZE_64 {
            uncompress_delta_var_byte_u64(remaining, out)
        } else {
            uncompress_delta_bin_pack_u64(remaining, out)
        };
    }
}

// ---------------------------------------------------------------------------
// Bin-pack outer loop
// ---------------------------------------------------------------------------

#[allow(clippy::uninit_vec)]
fn uncompress_delta_bin_pack_u32<'a>(input: &'a [u32], out: &mut Vec<u32>) -> &'a [u32] {
    let block_total = input[0] as usize;
    let mut init_offset = input[2];
    let mut inpos: usize = 3;

    let start = out.len();
    out.reserve(block_total);
    // SAFETY: each iteration writes exactly 128 slots (4 groups × 32) via
    // `&mut [u32; 32]`, and `block_total` is a multiple of 128 per the format,
    // so `start..start+block_total` is fully written before any slot is read.
    unsafe { out.set_len(start + block_total) };
    let mut outpos = start;
    let end = start + block_total;

    while outpos < end {
        let hdr = input[inpos];
        inpos += 1;
        let signs = [
            ((hdr >> 31) & 1) as usize,
            ((hdr >> 23) & 1) as usize,
            ((hdr >> 15) & 1) as usize,
            ((hdr >> 7) & 1) as usize,
        ];
        let bitlens = [
            ((hdr >> 24) & 0x7F) as usize,
            ((hdr >> 16) & 0x7F) as usize,
            ((hdr >> 8) & 0x7F) as usize,
            (hdr & 0x7F) as usize,
        ];

        for g in 0..4 {
            let group_off = outpos + g * GROUP_SIZE_32;
            let bitlen = bitlens[g];
            let dst: &mut [u32; GROUP_SIZE_32] = (&mut out[group_off..group_off + GROUP_SIZE_32])
                .try_into()
                .unwrap();
            unpack_group_u32(init_offset, &input[inpos..], dst, bitlen, signs[g]);
            inpos += bitlen;
            init_offset = dst[GROUP_SIZE_32 - 1];
        }

        outpos += BIT_PACKING_BLOCK_SIZE_32;
    }

    &input[inpos..]
}

#[allow(clippy::uninit_vec)]
fn uncompress_delta_bin_pack_u64<'a>(input: &'a [u64], out: &mut Vec<u64>) -> &'a [u64] {
    let block_total = (input[0] as u32) as usize;
    let mut init_offset = input[1];
    let mut inpos: usize = 2;

    let start = out.len();
    out.reserve(block_total);
    // SAFETY: each iteration writes exactly 256 slots (4 groups × 64) via
    // `&mut [u64; 64]`, and `block_total` is a multiple of 256 per the format,
    // so `start..start+block_total` is fully written before any slot is read.
    unsafe { out.set_len(start + block_total) };
    let mut outpos = start;
    let end = start + block_total;

    while outpos < end {
        let hdr = input[inpos];
        inpos += 1;
        let signs = [
            ((hdr >> 31) & 1) as usize,
            ((hdr >> 23) & 1) as usize,
            ((hdr >> 15) & 1) as usize,
            ((hdr >> 7) & 1) as usize,
        ];
        let bitlens = [
            ((hdr >> 24) & 0x7F) as usize,
            ((hdr >> 16) & 0x7F) as usize,
            ((hdr >> 8) & 0x7F) as usize,
            (hdr & 0x7F) as usize,
        ];

        for g in 0..4 {
            let group_off = outpos + g * GROUP_SIZE_64;
            let bitlen = bitlens[g];
            let dst: &mut [u64; GROUP_SIZE_64] = (&mut out[group_off..group_off + GROUP_SIZE_64])
                .try_into()
                .unwrap();
            unpack_group_u64(init_offset, &input[inpos..], dst, bitlen, signs[g]);
            inpos += bitlen;
            init_offset = dst[GROUP_SIZE_64 - 1];
        }

        outpos += BIT_PACKING_BLOCK_SIZE_64;
    }

    &input[inpos..]
}

// ---------------------------------------------------------------------------
// Per-bitlen group unpackers (specialised)
// ---------------------------------------------------------------------------

// Inner per-bitlen unroller. BITLEN must be in 1..=31; the BITLEN==0
// (constant-fill) and BITLEN==32 (raw copy) cases are handled by the
// dispatcher because the bit-unpack expression overflows at those extremes.
#[inline(always)]
fn unpack32_bits<const BITLEN: usize>(
    init_offset: u32,
    input: &[u32; BITLEN],
    out: &mut [u32; GROUP_SIZE_32],
) {
    let mask: u32 = (1u32 << BITLEN) - 1;
    let mut prev = init_offset;
    // LLVM unrolls this — trip count and BITLEN are constant.
    for (i, slot) in out.iter_mut().enumerate() {
        let bit_pos = i * BITLEN;
        let widx = bit_pos / 32;
        let boff = bit_pos % 32;
        let mut field = (input[widx] >> boff) & mask;
        if boff + BITLEN > 32 {
            field |= (input[widx + 1] << (32 - boff)) & mask;
        }
        let v = field.wrapping_add(prev);
        *slot = v;
        prev = v;
    }
}

#[inline(always)]
fn unpack32_zigzag_bits<const BITLEN: usize>(
    init_offset: u32,
    input: &[u32; BITLEN],
    out: &mut [u32; GROUP_SIZE_32],
) {
    let mask: u32 = (1u32 << BITLEN) - 1;
    let mut prev = init_offset;
    for (i, slot) in out.iter_mut().enumerate() {
        let bit_pos = i * BITLEN;
        let widx = bit_pos / 32;
        let boff = bit_pos % 32;
        let mut z = (input[widx] >> boff) & mask;
        if boff + BITLEN > 32 {
            z |= (input[widx + 1] << (32 - boff)) & mask;
        }
        let delta = (z >> 1) ^ (z & 1).wrapping_neg();
        let v = delta.wrapping_add(prev);
        *slot = v;
        prev = v;
    }
}

#[inline(always)]
fn unpack64_bits<const BITLEN: usize>(
    init_offset: u64,
    input: &[u64; BITLEN],
    out: &mut [u64; GROUP_SIZE_64],
) {
    let mask: u64 = (1u64 << BITLEN) - 1;
    let mut prev = init_offset;
    for (i, slot) in out.iter_mut().enumerate() {
        let bit_pos = i * BITLEN;
        let widx = bit_pos / 64;
        let boff = bit_pos % 64;
        let mut field = (input[widx] >> boff) & mask;
        if boff + BITLEN > 64 {
            field |= (input[widx + 1] << (64 - boff)) & mask;
        }
        let v = field.wrapping_add(prev);
        *slot = v;
        prev = v;
    }
}

#[inline(always)]
fn unpack64_zigzag_bits<const BITLEN: usize>(
    init_offset: u64,
    input: &[u64; BITLEN],
    out: &mut [u64; GROUP_SIZE_64],
) {
    let mask: u64 = (1u64 << BITLEN) - 1;
    let mut prev = init_offset;
    for (i, slot) in out.iter_mut().enumerate() {
        let bit_pos = i * BITLEN;
        let widx = bit_pos / 64;
        let boff = bit_pos % 64;
        let mut z = (input[widx] >> boff) & mask;
        if boff + BITLEN > 64 {
            z |= (input[widx + 1] << (64 - boff)) & mask;
        }
        let delta = (z >> 1) ^ (z & 1).wrapping_neg();
        let v = delta.wrapping_add(prev);
        *slot = v;
        prev = v;
    }
}

// Dispatcher macros expand to a flat `match bitlen { ... }` with one arm per
// concrete BITLEN, instantiating the inline'd const-generic worker. Each arm
// pulls a typed `&[T; N]` slice prefix so the worker has no bounds checks to
// emit. The macro is invoked with the full list of bitlens to make it
// explicit and grep-friendly.

macro_rules! dispatch32 {
    ($bitlen:expr, $worker:ident, $init:expr, $input:expr, $out:expr, [$($n:literal),+]) => {
        match $bitlen {
            $($n => $worker::<$n>(
                $init,
                $input.first_chunk::<$n>().unwrap(),
                $out,
            ),)+
            _ => unreachable!(),
        }
    };
}

macro_rules! dispatch64 {
    ($bitlen:expr, $worker:ident, $init:expr, $input:expr, $out:expr, [$($n:literal),+]) => {
        match $bitlen {
            $($n => $worker::<$n>(
                $init,
                $input.first_chunk::<$n>().unwrap(),
                $out,
            ),)+
            _ => unreachable!(),
        }
    };
}

#[inline]
fn unpack_group_u32(
    init_offset: u32,
    input: &[u32],
    out: &mut [u32; GROUP_SIZE_32],
    bitlen: usize,
    sign: usize,
) {
    if bitlen == 0 {
        out.fill(init_offset);
        return;
    }
    if bitlen == 32 {
        out.copy_from_slice(&input[..GROUP_SIZE_32]);
        return;
    }
    if sign == 0 {
        dispatch32!(
            bitlen,
            unpack32_bits,
            init_offset,
            input,
            out,
            [
                1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
                24, 25, 26, 27, 28, 29, 30, 31
            ]
        );
    } else {
        dispatch32!(
            bitlen,
            unpack32_zigzag_bits,
            init_offset,
            input,
            out,
            [
                1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
                24, 25, 26, 27, 28, 29, 30, 31
            ]
        );
    }
}

#[inline]
fn unpack_group_u64(
    init_offset: u64,
    input: &[u64],
    out: &mut [u64; GROUP_SIZE_64],
    bitlen: usize,
    sign: usize,
) {
    if bitlen == 0 {
        out.fill(init_offset);
        return;
    }
    if bitlen == 64 {
        out.copy_from_slice(&input[..GROUP_SIZE_64]);
        return;
    }
    if sign == 0 {
        dispatch64!(
            bitlen,
            unpack64_bits,
            init_offset,
            input,
            out,
            [
                1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
                24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44,
                45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63
            ]
        );
    } else {
        dispatch64!(
            bitlen,
            unpack64_zigzag_bits,
            init_offset,
            input,
            out,
            [
                1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
                24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44,
                45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63
            ]
        );
    }
}

// ---------------------------------------------------------------------------
// delta-var-byte (unchanged from initial port)
// ---------------------------------------------------------------------------

fn uncompress_delta_var_byte_u32<'a>(input: &'a [u32], out: &mut Vec<u32>) -> &'a [u32] {
    let outlen = input[0] as usize;
    let inlen = input[1] as usize;
    let rest = &input[inlen..];
    let block = &input[..inlen];

    out.reserve(outlen);

    let mut inpos: usize = 2;
    let mut shift_in: i32 = 24;
    let mut init_offset: u32 = 0;
    let mut delta: u32 = 0;
    let mut shift_out: u32 = 0;

    while inpos < block.len() {
        let c = block[inpos] >> shift_in;

        shift_in -= 8;
        if shift_in < 0 {
            shift_in = 24;
            inpos += 1;
        }

        delta = delta.wrapping_add((c & 0x7F).wrapping_shl(shift_out));
        shift_out += 7;
        if c & 0x80 == 0 {
            shift_out = 0;
            let v = delta.wrapping_add(init_offset);
            out.push(v);
            init_offset = v;
            delta = 0;
        }
    }

    rest
}

fn uncompress_delta_var_byte_u64<'a>(input: &'a [u64], out: &mut Vec<u64>) -> &'a [u64] {
    let outlen = (input[0] as u32) as usize;
    let inlen = (input[0] >> 32) as usize;
    let rest = &input[inlen..];
    let block = &input[..inlen];

    out.reserve(outlen);

    let mut inpos: usize = 1;
    let mut shift_in: i32 = 56;
    let mut init_offset: u64 = 0;
    let mut delta: u64 = 0;
    let mut shift_out: u32 = 0;

    while inpos < block.len() {
        let c = block[inpos] >> shift_in;

        shift_in -= 8;
        if shift_in < 0 {
            shift_in = 56;
            inpos += 1;
        }

        delta = delta.wrapping_add((c & 0x7F).wrapping_shl(shift_out));
        shift_out += 7;
        if c & 0x80 == 0 {
            shift_out = 0;
            let v = delta.wrapping_add(init_offset);
            out.push(v);
            init_offset = v;
            delta = 0;
        }
    }

    rest
}
