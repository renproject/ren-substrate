#![cfg_attr(not(feature = "std"), no_std)]

#[macro_use]
extern crate alloc;

extern crate hex;

// use frame_support::sp_runtime::print;

use frame_support::{decl_error, decl_event, decl_module, decl_storage, ensure, StorageMap};
use frame_system::{self as system, ensure_signed};
use sp_std::vec::Vec;

mod ecrecover;
mod verify_signature;

/// The pallet's configuration trait.
pub trait Trait: system::Trait {
	/// The overarching event type.
	type Event: From<Event<Self>> + Into<<Self as system::Trait>::Event>;
}

// This pallet's events.
decl_event! {
	pub enum Event<T> where AccountId = <T as system::Trait>::AccountId {
		/// Event emitted when assets are minted.
		AssetsMinted(AccountId, u8, u128),
		/// Event emitted when assets are burnt.
		AssetsBurnt(AccountId, u8, Vec<u8>, u128),
		/// Event emitted when assets are transferred.
		AssetsTransferred(AccountId, AccountId, u8, u128),
	}
}

// This pallet's errors.
decl_error! {
	pub enum Error for Module<T: Trait> {
		/// The mint signature is invalid
		InvalidMintSignature,
		/// The mint signature has already been used
		SignatureAlreadyUsed,
		/// The amount being burnt is greater than the account's balance
		InsufficientBalance,
	}
}

// This pallet's storage items.
decl_storage! {
	trait Store for Module<T: Trait> as TemplateModule {
		// The storage item for asset balances.
		Balances: map hasher(blake2_128_concat) T::AccountId => u128;

		Signatures: map hasher(blake2_128_concat) Vec<u8> => bool;
	}
}

// The pallet's dispatchable functions.
decl_module! {
	/// The module declaration.
	pub struct Module<T: Trait> for enum Call where  origin: T::Origin {
		// Initializing errors
		// this includes information about your errors in the node's metadata.
		// it is needed only if you are using errors in your pallet
		type Error = Error<T>;

		// A default function for depositing events
		fn deposit_event() = default;

		/// Allow a user to mint if they have a valid signature
		#[weight = 10_000]
		fn mint(
			origin,
			p_hash: Vec<u8>,
			amount: u128,
			n_hash: Vec<u8>,
			sig: Vec<u8>,
		) {
			// Determine who is calling the function
			let sender = ensure_signed(origin)?;

			// TODO: Convert sender to bytes directly.
			// let sender_bytes: Vec<u8> = hex::decode(sender.to_string()).unwrap();
			let sender_bytes = hex::decode("7ddfa2e5435027f6e13ca8db2f32ebd5551158bb").unwrap();

			// Verify that the signature is valid
			ensure!(verify_signature::verify_signature(&p_hash, amount, &sender_bytes, &n_hash, &sig), Error::<T>::InvalidMintSignature);

			// Verify that the signature hasn't been used previously
			ensure!(!Signatures::contains_key(&sig), Error::<T>::SignatureAlreadyUsed);

			// Store signature so it can't be used again.
			Signatures::insert(&sig, true);

			// If user doesn't have a balance, initiate it to 0.
			if !Balances::<T>::contains_key(&sender) {
				Balances::<T>::insert(&sender, 0);
			}

			// Increment user's balance.
			Balances::<T>::insert(&sender, Balances::<T>::get(&sender) + amount);

			Self::deposit_event(RawEvent::AssetsMinted(sender, 0, amount));
		}

		/// Allow a user to burn assets
		#[weight = 10_000]
		fn burn(
			origin,
			to: Vec<u8>,
			amount: u128,
		) {
			// Determine who is calling the function
			let sender = ensure_signed(origin)?;

			// Verify the user's balance
			ensure!(Balances::<T>::contains_key(&sender), Error::<T>::InsufficientBalance);
			ensure!(Balances::<T>::get(&sender) >= amount, Error::<T>::InsufficientBalance);

			// Decrement user's balance.
			Balances::<T>::insert(&sender, Balances::<T>::get(&sender) - amount);

			Self::deposit_event(RawEvent::AssetsBurnt(sender, 0, to, amount));
		}

		/// Transfer
		#[weight = 10_000]
		fn transfer(
			origin,
			recipient: T::AccountId,
			amount: u128,
		) {
			// Determine who is calling the function
			let sender = ensure_signed(origin)?;

			// Verify the user's balance
			ensure!(Balances::<T>::contains_key(&sender), Error::<T>::InsufficientBalance);
			ensure!(Balances::<T>::get(&sender) >= amount, Error::<T>::InsufficientBalance);

			// Decrement user's balance.
			Balances::<T>::insert(&sender, Balances::<T>::get(&sender) - amount);

			// If user doesn't have a balance, initiate it to 0.
			if !Balances::<T>::contains_key(&recipient) {
				Balances::<T>::insert(&recipient, 0);
			}

			// Increment user's balance.
			Balances::<T>::insert(&recipient, Balances::<T>::get(&recipient) + amount);

			Self::deposit_event(RawEvent::AssetsTransferred(sender, recipient, 0, amount));
		}
	}
}