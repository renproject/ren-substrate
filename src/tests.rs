//! Unit tests for the airdrop module.

#![cfg(test)]

use super::*;
use frame_support::{assert_noop, assert_ok};
use mock::{RenToken, ExtBuilder, Origin, System, TestEvent, ALICE, BOB, CHARLIE};
use sp_runtime::traits::BadOrigin;

use crate::verify_signature::{verify_signature};

#[test]
fn can_verify_signature() {
	ExtBuilder::default().build().execute_with(|| {
		assert_eq!(
			verify_signature(
				&hex::decode("c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470").unwrap(), // phash
				5000, // amount
				&hex::decode("d43593c715fdd31c61141abd04a99fd6822c8558854ccde39a5684e7a56da27d").unwrap(), // _to
				&hex::decode("e96cc92771222bd8f674ddf4ef6a4264e38030e90380fb215cb145591ed803e9").unwrap(), // nhash
				&hex::decode("1beaeea7cb5433659979ba0ba17bc0174c87b6208ea0fa82e1478a74b3ded5a27324239b8f0ef31f54cc56deb32bb8962803ecf399eac7ade08f291ae03f6a1f1c").unwrap() // signature
			),
			true
		);
	});
}

#[test]
fn can_mint() {
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

		assert_ok!(
			RenToken::mint(
				Origin::signed(ALICE),
				hex::decode("c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470").unwrap(), // phash
				5000, // amount
				hex::decode("6d9b77f6070c8dd4e6e6ad2217d6aa6ef48a06e27a3c4a189e0a9f2c59db409e").unwrap(), // nhash
				hex::decode("130bef45db4f2b7ccf2689cfd8214e7dbdeb4263de1c26bcd1c702ce4a4093b97d49c835f8225e52103047eef3feca2e41681ea5a27dc6ab84a26efc49f05f971b").unwrap() // signature
			)
		);

		assert_ok!(
			RenToken::mint(
				Origin::signed(ALICE),
				hex::decode("c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470").unwrap(), // phash
				6000, // amount
				hex::decode("7c5e9fad22654694c5bbbce509c2003b10cf90798cd84b1fb1851cdfba58d52e").unwrap(), // nhash
				hex::decode("776abdea3287da906a5c72dd08f9be1b0a160374ae7045b028a17098f98970245d173aa73d1e8ae99adf23ccf92030e6c4a390c62952f1dffb37bbcfde4bef171b").unwrap() // signature
			)
		);

		assert_ok!(
			RenToken::mint(
				Origin::signed(ALICE),
				hex::decode("c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470").unwrap(), // phash
				95000, // amount
				hex::decode("81e25aafbe2fb3ea02de043f5e13118c087a12d6871198cc97d160180fafcca2").unwrap(), // nhash
				hex::decode("09f05f67a282e483d7e064ad1f2382dfedf6df11f55d42c86a47e6f54e0dd004280b395a923a8a60a93b6986217bb67adb4cc066ad4444dc28ec92d1de23b5f11b").unwrap() // signature
			)
		);
	});
}
