use crate::{
    PedersenProvingKey, ProvingKey,
    curve::{G1Affine, G2Affine},
    parsing::{
        ParseError,
        utils::{
            FIELD_BYTES, G1_AFFINE_BYTES, G2_AFFINE_BYTES, bit_reverse_to_natural, decode_g1_run,
            decode_g2_run, g1_from_uncompressed, g2_from_uncompressed, kept_indices, read_domain,
        },
    },
    types::Domain,
};

impl ProvingKey {
    pub fn streaming_parser(check_points: bool) -> ProvingKeyParser {
        ProvingKeyParser::new(check_points)
    }
}

const DOMAIN_BYTES: usize = 8 + 5 * FIELD_BYTES + 1;

// Vec states use `Option<usize>` for the remaining-item counter:
// `None` = need to read the u32 length; `Some(n)` = decode body for n more.
const N_G1_SINGLES: u8 = 3; // g1_alpha, g1_beta, g1_delta
const N_G1_VECS: u8 = 4; // g1_a, g1_b, g1_z, g1_k
const N_G2_SINGLES: u8 = 2; // g2_beta, g2_delta
const N_U64S: u8 = 3; // nb_wires, nb_infinity_a, nb_infinity_b
const N_BOOL_VECS: u8 = 2; // infinity_a, infinity_b

#[derive(Clone, Copy)]
enum State {
    Domain,
    G1Single(u8),
    G1Vec(u8, Option<usize>),
    G2Single(u8),
    G2Vec(Option<usize>),
    U64(u8),
    BoolBody(u8, usize),
    NbCommitments,
    /// `(idx, total, sub, remaining)` — sub 0=basis, 1=basis_exp_sigma.
    Pedersen(u32, u32, u8, Option<usize>),
    Done,
}

/// Unwrap an `Option`; on `None`, return `Ok(false)` from the enclosing
/// `try_advance` to signal "need more bytes".
macro_rules! need {
    ($opt:expr) => {
        match $opt {
            Some(v) => v,
            None => return Ok(false),
        }
    };
}

/// Drive `feed_body` for a vec-body state. Macro (not a method) so the call
/// site can split-borrow `body` / `body_head` from the destination field.
macro_rules! drive_body {
    ($self:ident, $buf:ident, $pos:ident, $rem:expr, $stride:expr, $dst:expr, $decode:ident) => {{
        let check_points = $self.check_points;
        let dst = $dst;
        need!(feed_body(
            &mut $self.body,
            &mut $self.body_head,
            $buf,
            $pos,
            $rem,
            $stride,
            |bytes, take| $decode(bytes, take, check_points, dst),
        )?)
    }};
}

/// Incremental parser for the gnark Groth16 proving-key wire format.
///
/// Parses each point directly into the destination `Vec`s without buffering
/// the full input. Peak memory is O(parsed `ProvingKey`) plus a ≤128 B carry
/// window — the network buffer is freed chunk-by-chunk as it's consumed.
pub struct ProvingKeyParser {
    /// Unconsumed tail from the previous `feed`.
    carry: Vec<u8>,
    /// Staging buffer for vector-body wire bytes. See [`feed_body`].
    body: Vec<u8>,
    body_head: usize,
    state: State,
    check_points: bool,
    domain: Option<Domain>,
    g1_singles: [G1Affine; 3],
    g1_vecs: [Vec<G1Affine>; 4],
    g2_singles: [G2Affine; 2],
    g2_b: Vec<G2Affine>,
    u64s: [u64; 3],
    bools: [Vec<bool>; 2],
    commitment_keys: Vec<PedersenProvingKey>,
    /// Active Pedersen commitment: `[basis, basis_exp_sigma]`.
    pending_pedersen: [Vec<G1Affine>; 2],
}

/// Target bytes per rayon decode dispatch. 1 MiB ≈ 16 k G1 points (8 k pairs),
/// large enough that rayon fork/join overhead amortises across the work
/// (matching the one-shot parser's single-dispatch-per-vector cost).
const BODY_BATCH_BYTES: usize = 1 << 20;

/// `body` capacity: one full batch plus headroom so we can keep staging
/// while a decode is in flight without reallocating.
const BODY_CAPACITY: usize = 2 * BODY_BATCH_BYTES;

impl ProvingKeyParser {
    pub fn new(check_points: bool) -> Self {
        Self {
            carry: Vec::with_capacity(G2_AFFINE_BYTES),
            body: Vec::with_capacity(BODY_CAPACITY),
            body_head: 0,
            state: State::Domain,
            check_points,
            domain: None,
            g1_singles: [G1Affine::identity(); 3],
            g1_vecs: [const { Vec::new() }; 4],
            g2_singles: [G2Affine::identity(); 2],
            g2_b: Vec::new(),
            u64s: [0; 3],
            bools: [const { Vec::new() }; 2],
            commitment_keys: Vec::new(),
            pending_pedersen: [const { Vec::new() }; 2],
        }
    }

    /// Append `chunk` and consume as much as the state machine can. Safe with
    /// arbitrary chunk sizes — including ones that split an item.
    ///
    /// Fast path: when the carry is empty (steady state), the parser reads
    /// directly from `chunk`. The only bytes copied are the previous carry's
    /// leftover (≤128 B) and the new tail (≤128 B), not the full chunk.
    pub fn feed(&mut self, chunk: &[u8]) -> Result<(), ParseError> {
        // Take carry out so we can pass &mut self to try_advance while also
        // borrowing the carry slice. Put it back at the end.
        let mut carry = std::mem::take(&mut self.carry);
        let mut chunk_off = 0;

        // Phase 1: drain the leftover from the previous feed by topping it
        // up from the head of `chunk`, one item at a time.
        while !carry.is_empty() {
            let mut pos = 0;
            self.drain_buffer(&carry, &mut pos)?;
            if pos > 0 {
                carry.drain(..pos);
            }
            if carry.is_empty() || chunk_off == chunk.len() {
                break;
            }
            let item_size = item_size_for(self.state);
            if item_size == 0 {
                break;
            }
            let bytes_needed = item_size.saturating_sub(carry.len()).max(1);
            let take = bytes_needed.min(chunk.len() - chunk_off);
            carry.extend_from_slice(&chunk[chunk_off..chunk_off + take]);
            chunk_off += take;
        }

        // Phase 2: carry drained — parse the rest of `chunk` in place.
        if carry.is_empty() && chunk_off < chunk.len() {
            let mut pos = chunk_off;
            self.drain_buffer(chunk, &mut pos)?;
            if pos < chunk.len() {
                carry.extend_from_slice(&chunk[pos..]);
            }
        }

        self.carry = carry;
        Ok(())
    }

    /// Consume the parser. Errors if the input ended mid-section or had
    /// trailing bytes after the proving key.
    pub fn finish(mut self) -> Result<ProvingKey, ParseError> {
        let carry = std::mem::take(&mut self.carry);
        let mut pos = 0;
        self.drain_buffer(&carry, &mut pos)?;
        if !matches!(self.state, State::Done) {
            return Err(ParseError::ProvingKey(format!(
                "unexpected end of stream: {} bytes remaining in window",
                carry.len() - pos
            )));
        }
        if pos < carry.len() {
            return Err(ParseError::ProvingKey(format!(
                "{} trailing bytes after proving key",
                carry.len() - pos
            )));
        }
        let domain = self.domain.expect("Done implies domain parsed");
        let [g1_alpha, g1_beta, g1_delta] = self.g1_singles;
        let [g1_a, g1_b, mut g1_z, g1_k] = self.g1_vecs;
        bit_reverse_to_natural(&mut g1_z, domain.cardinality as usize);
        let [g2_beta, g2_delta] = self.g2_singles;
        let [nb_wires, nb_infinity_a, nb_infinity_b] = self.u64s;
        let [infinity_a, infinity_b] = self.bools;
        let idx_a = kept_indices(&infinity_a);
        let idx_b = kept_indices(&infinity_b);
        Ok(ProvingKey {
            domain,
            g1_alpha,
            g1_beta,
            g1_delta,
            g1_a,
            g1_b,
            g1_z,
            g1_k,
            g2_beta,
            g2_delta,
            g2_b: self.g2_b,
            nb_wires,
            nb_infinity_a,
            nb_infinity_b,
            infinity_a,
            infinity_b,
            idx_a,
            idx_b,
            commitment_keys: self.commitment_keys,
        })
    }

    fn drain_buffer(&mut self, buf: &[u8], pos: &mut usize) -> Result<(), ParseError> {
        while self.try_advance(buf, pos)? {}
        Ok(())
    }

    /// Advance one step. `Ok(true)` = made progress; call again. `Ok(false)`
    /// = out of input for the current section, or `Done`.
    fn try_advance(&mut self, buf: &[u8], pos: &mut usize) -> Result<bool, ParseError> {
        match self.state {
            State::Domain => {
                let slice = need!(peek(buf, *pos, DOMAIN_BYTES));
                let mut r = slice;
                self.domain = Some(read_domain(&mut r)?);
                *pos += DOMAIN_BYTES;
                self.state = State::G1Single(0);
            }
            State::G1Single(slot) => {
                let slice = need!(peek(buf, *pos, G1_AFFINE_BYTES));
                self.g1_singles[slot as usize] = g1_from_uncompressed(slice, self.check_points)?;
                *pos += G1_AFFINE_BYTES;
                self.state = if slot + 1 < N_G1_SINGLES {
                    State::G1Single(slot + 1)
                } else {
                    State::G1Vec(0, None)
                };
            }
            State::G1Vec(slot, None) => {
                let len = need!(read_u32_be(buf, pos)) as usize;
                self.g1_vecs[slot as usize].reserve_exact(len);
                self.state = State::G1Vec(slot, Some(len));
            }
            State::G1Vec(slot, Some(remaining)) => {
                let new_rem = drive_body!(
                    self,
                    buf,
                    pos,
                    remaining,
                    G1_AFFINE_BYTES,
                    &mut self.g1_vecs[slot as usize],
                    decode_g1_run
                );
                self.state = if new_rem > 0 {
                    State::G1Vec(slot, Some(new_rem))
                } else if slot + 1 < N_G1_VECS {
                    State::G1Vec(slot + 1, None)
                } else {
                    State::G2Single(0)
                };
            }
            State::G2Single(slot) => {
                let slice = need!(peek(buf, *pos, G2_AFFINE_BYTES));
                self.g2_singles[slot as usize] = g2_from_uncompressed(slice, self.check_points)?;
                *pos += G2_AFFINE_BYTES;
                self.state = if slot + 1 < N_G2_SINGLES {
                    State::G2Single(slot + 1)
                } else {
                    State::G2Vec(None)
                };
            }
            State::G2Vec(None) => {
                let len = need!(read_u32_be(buf, pos)) as usize;
                self.g2_b.reserve_exact(len);
                self.state = State::G2Vec(Some(len));
            }
            State::G2Vec(Some(remaining)) => {
                let new_rem = drive_body!(
                    self,
                    buf,
                    pos,
                    remaining,
                    G2_AFFINE_BYTES,
                    &mut self.g2_b,
                    decode_g2_run
                );
                self.state = if new_rem > 0 {
                    State::G2Vec(Some(new_rem))
                } else {
                    State::U64(0)
                };
            }
            State::U64(slot) => {
                self.u64s[slot as usize] = need!(read_u64_be(buf, pos));
                self.state = if slot + 1 < N_U64S {
                    State::U64(slot + 1)
                } else {
                    let n = self.u64s[0] as usize; // nb_wires
                    self.bools[0].reserve_exact(n);
                    State::BoolBody(0, n)
                };
            }
            State::BoolBody(slot, remaining) => {
                let new_rem = need!(consume_bools(
                    buf,
                    pos,
                    remaining,
                    &mut self.bools[slot as usize]
                ));
                self.state = if new_rem > 0 {
                    State::BoolBody(slot, new_rem)
                } else if slot + 1 < N_BOOL_VECS {
                    let n = self.u64s[0] as usize; // nb_wires
                    self.bools[(slot + 1) as usize].reserve_exact(n);
                    State::BoolBody(slot + 1, n)
                } else {
                    State::NbCommitments
                };
            }
            State::NbCommitments => {
                let total = need!(read_u32_be(buf, pos));
                self.commitment_keys.reserve_exact(total as usize);
                self.state = if total == 0 {
                    State::Done
                } else {
                    State::Pedersen(0, total, 0, None)
                };
            }
            State::Pedersen(idx, total, sub, None) => {
                let len = need!(read_u32_be(buf, pos)) as usize;
                self.pending_pedersen[sub as usize].reserve_exact(len);
                self.state = State::Pedersen(idx, total, sub, Some(len));
            }
            State::Pedersen(idx, total, sub, Some(remaining)) => {
                let new_rem = drive_body!(
                    self,
                    buf,
                    pos,
                    remaining,
                    G1_AFFINE_BYTES,
                    &mut self.pending_pedersen[sub as usize],
                    decode_g1_run
                );
                self.state = if new_rem > 0 {
                    State::Pedersen(idx, total, sub, Some(new_rem))
                } else if sub == 0 {
                    State::Pedersen(idx, total, 1, None)
                } else {
                    self.flush_pedersen();
                    if idx + 1 == total {
                        State::Done
                    } else {
                        State::Pedersen(idx + 1, total, 0, None)
                    }
                };
            }
            State::Done => return Ok(false),
        }
        Ok(true)
    }

    fn flush_pedersen(&mut self) {
        let [basis, basis_exp_sigma] =
            std::mem::replace(&mut self.pending_pedersen, [const { Vec::new() }; 2]);
        self.commitment_keys.push(PedersenProvingKey {
            basis,
            basis_exp_sigma,
        });
    }
}

fn peek(buf: &[u8], pos: usize, n: usize) -> Option<&[u8]> {
    if buf.len() - pos < n {
        None
    } else {
        Some(&buf[pos..pos + n])
    }
}

/// Minimum bytes the current state needs to advance once. Drives `feed`'s
/// carry-top-up phase so the parser pays at most one item of memcpy per
/// cross-chunk boundary. `Done` returns 0 — the loop bails out on that.
fn item_size_for(state: State) -> usize {
    match state {
        State::Domain => DOMAIN_BYTES,
        State::G1Single(_) | State::G1Vec(_, Some(_)) | State::Pedersen(_, _, _, Some(_)) => {
            G1_AFFINE_BYTES
        }
        State::G2Single(_) | State::G2Vec(Some(_)) => G2_AFFINE_BYTES,
        State::G1Vec(_, None)
        | State::G2Vec(None)
        | State::NbCommitments
        | State::Pedersen(_, _, _, None) => 4,
        State::U64(_) => 8,
        State::BoolBody(..) => 1,
        State::Done => 0,
    }
}

/// Stage wire bytes into `body` and dispatch a rayon decode whenever the
/// staged-but-unconsumed window reaches a full batch (or holds the rest of
/// the vector). Returns `None` if the call made no progress (caller reports
/// `NeedMore`); `Some(new_remaining)` otherwise.
fn feed_body<F>(
    body: &mut Vec<u8>,
    body_head: &mut usize,
    buf: &[u8],
    pos: &mut usize,
    remaining: usize,
    stride: usize,
    mut decode: F,
) -> Result<Option<usize>, ParseError>
where
    F: FnMut(&[u8], usize) -> Result<(), ParseError>,
{
    if remaining == 0 {
        return Ok(Some(0));
    }
    let pos_before = *pos;
    let mut rem = remaining;
    while rem > 0 {
        // Stage as many bytes as we can — bounded by chunk, body capacity,
        // and what this vector still needs.
        let need_bytes_total = rem * stride;
        let still_needed = need_bytes_total.saturating_sub(body.len() - *body_head);
        let take = (buf.len() - *pos)
            .min(body.capacity() - body.len())
            .min(still_needed);
        if take > 0 {
            body.extend_from_slice(&buf[*pos..*pos + take]);
            *pos += take;
        }

        // Flush a decode batch if we have a full `BODY_BATCH_BYTES` window,
        // or we already hold the remainder of the vector.
        let avail_for_vec = (body.len() - *body_head).min(need_bytes_total);
        let is_final = avail_for_vec == need_bytes_total;
        let is_full_batch = avail_for_vec >= BODY_BATCH_BYTES;
        if !is_full_batch && !is_final {
            break;
        }
        let pts = avail_for_vec.min(BODY_BATCH_BYTES) / stride;
        let nbytes = pts * stride;
        decode(&body[*body_head..*body_head + nbytes], pts)?;
        *body_head += nbytes;
        rem -= pts;

        // Compact when the head has crossed half-capacity. Cheaper than
        // `Vec::drain` because the tail is typically small.
        if *body_head >= body.capacity() / 2 {
            let tail_len = body.len() - *body_head;
            body.copy_within(*body_head.., 0);
            body.truncate(tail_len);
            *body_head = 0;
        }
    }
    if rem == remaining && *pos == pos_before {
        Ok(None)
    } else {
        Ok(Some(rem))
    }
}

fn consume_bools(
    buf: &[u8],
    pos: &mut usize,
    remaining: usize,
    dst: &mut Vec<bool>,
) -> Option<usize> {
    if remaining == 0 {
        return Some(0);
    }
    let avail = buf.len() - *pos;
    if avail == 0 {
        return None;
    }
    let take = avail.min(remaining);
    dst.extend(buf[*pos..*pos + take].iter().map(|&b| b != 0));
    *pos += take;
    Some(remaining - take)
}

fn read_u32_be(buf: &[u8], pos: &mut usize) -> Option<u32> {
    let slice = peek(buf, *pos, 4)?;
    *pos += 4;
    Some(u32::from_be_bytes(slice.try_into().unwrap()))
}

fn read_u64_be(buf: &[u8], pos: &mut usize) -> Option<u64> {
    let slice = peek(buf, *pos, 8)?;
    *pos += 8;
    Some(u64::from_be_bytes(slice.try_into().unwrap()))
}
