#![feature(iter_array_chunks)]
#![feature(array_chunks)]


pub mod boolean_tree;
pub mod primitive;
pub mod sbox;
pub mod state;
pub mod key_schedule;

pub use state::State;
pub use primitive::FHEByte;
pub use key_schedule::Key;

