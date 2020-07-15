//! Unit tests for the airdrop module.

#![cfg(test)]

use super::*;
use frame_support::{assert_noop, assert_ok};
use mock::{RenToken, ExtBuilder, Origin, System, TestEvent, ALICE, BOB, CHARLIE};
use sp_runtime::traits::BadOrigin;

use crate::verify_signature::verify_signature;

#[test]
fn can_verify_signature() {
	ExtBuilder::default().build().execute_with(|| {
		assert_ok!(
			RenToken::mint(
				Origin::signed(ALICE),
				hex::decode("c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470").unwrap(), // phash
				5000, // amount
				hex::decode("e96cc92771222bd8f674ddf4ef6a4264e38030e90380fb215cb145591ed803e9").unwrap(), // nhash
				hex::decode("1beaeea7cb5433659979ba0ba17bc0174c87b6208ea0fa82e1478a74b3ded5a27324239b8f0ef31f54cc56deb32bb8962803ecf399eac7ade08f291ae03f6a1f1c").unwrap() // signature
			)
		);
	});
}
