use sp_std::vec::Vec;

use crate::ecrecover::keccak;
use crate::ecrecover::ecrecover;

const RENVM_SPLIT_PUBLIC_KEY: &str = "0000000000000000000000004b939fc8ade87cb50b78987b1dda927460dc456a";
// TODO: Change to Currency identifier.
const RENVM_BTC_IDENTIFIER: &str = "0a9add98c076448cbcfacf5e457da12ddbef4a8f";

const P_HASH_OFFSET: usize = 0;
const P_HASH_LENGTH: usize = 32;
const AMOUNT_OFFSET: usize = P_HASH_OFFSET + P_HASH_LENGTH;
const AMOUNT_LENGTH: usize = 32;
const TOKEN_OFFSET: usize = AMOUNT_OFFSET + AMOUNT_LENGTH;
const TOKEN_LENGTH: usize = 32;
const TO_OFFSET: usize = TOKEN_OFFSET + TOKEN_LENGTH;
const TO_LENGTH: usize = 32;
const N_HASH_OFFSET: usize = TO_OFFSET + TO_LENGTH;
const N_HASH_LENGTH: usize = 32;

// ABI-encode the values for creating the signature hash.
fn encode(
	_p_hash: &Vec<u8>,
	_amount: u128,
	_token: &Vec<u8>,
	_to: &Vec<u8>,
	_n_hash: &Vec<u8>,
) -> Vec<u8> {

	let mut result = vec![0; N_HASH_OFFSET + N_HASH_LENGTH];
	
	let amount_bytes = _amount.to_be_bytes();

	for (i, val) in (&_p_hash[0..]).iter().enumerate() {
        result[i + (P_HASH_LENGTH - _p_hash.len()) + P_HASH_OFFSET] = *val;
	}
	for (i, val) in (&amount_bytes[0..]).iter().enumerate() {
        result[i + (AMOUNT_LENGTH - amount_bytes.len()) + AMOUNT_OFFSET] = *val;
	}
	for (i, val) in (&_token[0..]).iter().enumerate() {
        result[i + (TOKEN_LENGTH - _token.len()) + TOKEN_OFFSET] = *val;
	}
	for (i, val) in (&_to[0..]).iter().enumerate() {
        result[i + (TO_LENGTH - _to.len()) + TO_OFFSET] = *val;
	}
	for (i, val) in (&_n_hash[0..]).iter().enumerate() {
        result[i + (N_HASH_LENGTH - _n_hash.len()) + N_HASH_OFFSET] = *val;
    }

	result
}

// Verify that the signature has been signed by RenVM.
pub fn verify_signature(
	_p_hash: &Vec<u8>,
	_amount: u128,
	_to: &Vec<u8>,
	_n_hash: &Vec<u8>,
	_sig: &Vec<u8>,
) -> bool {
	let ren_btc_identifier = hex::decode(RENVM_BTC_IDENTIFIER).unwrap();

	let encoded = encode(
		_p_hash,
		_amount, // _amount,
		&ren_btc_identifier, // _token
		_to,
		_n_hash
	);

	let signed_message_hash = keccak(&encoded[..]);
	let recovered_address = ecrecover(signed_message_hash, _sig).unwrap();

	// Expected address is RenVM's split public key.
	let expected_address = hex::decode(RENVM_SPLIT_PUBLIC_KEY).unwrap();

	return recovered_address.eq(&expected_address);
}
