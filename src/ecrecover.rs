extern crate secp256k1;
extern crate tiny_keccak;

use secp256k1::{recover, Message, RecoveryId, Signature};
use sp_std::cmp::min;

use sp_std::vec::{Vec};

// Return the keccak256 hash of the input.
pub fn keccak(input: &[u8]) -> [u8; 32] {
    let mut hash = [0u8; 32];
    tiny_keccak::Keccak::keccak256(&input, &mut hash);
    hash
}

const R_OFFSET: usize = 0;
const R_LENGTH: usize = 32;
const S_OFFSET: usize = R_OFFSET + R_LENGTH;
const S_LENGTH: usize = 32;
const V_OFFSET: usize = S_OFFSET + S_LENGTH;
const V_LENGTH: usize = 1;

// Modified from parity's Ethereum precompiles code. Recovers the secp256k1
// public key used to generate the signature of the hash.
pub fn ecrecover(hash: [u8; 32], sig: &Vec<u8>) -> Result<Vec<u8>, secp256k1::Error> {
    let sig_start = min(R_OFFSET, sig.len());
    let sig_end = min(S_OFFSET + S_LENGTH, sig.len());
    let mut rs = [0u8; 64];
    for (i, val) in (&sig[sig_start..sig_end]).iter().enumerate() {
        rs[i] = *val;
    }

    // v should be 0 or 1 but is passed in as 27 or 28.
    let v = if sig.len() > V_OFFSET + V_LENGTH - 1 {
        (sig[V_OFFSET + V_LENGTH - 1] as i8 - 27) as u8
    } else {
        (0) as u8
    };
    if v != 0 && v != 1 {
        return Ok(vec![0u8; 0]);
    }

    let message = Message::parse(&hash);
    let rec_id = RecoveryId::parse(v)?;
    let sig = Signature::parse(&rs);

    let key = recover(&message, &sig, &rec_id)?;
    let ret = key.serialize();
    let ret = keccak(&ret[1..65]);
    let mut output = vec![0u8; 12];
    output.extend_from_slice(&ret[12..32]);
    Ok(output)
}
