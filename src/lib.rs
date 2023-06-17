#![doc = include_str!("../README.md")]

pub mod basic_sharing;
#[allow(dead_code)]
mod geometry;
pub mod wrapped_sharing;

#[cfg(feature = "fuzz_tests")]
#[cfg(test)]
mod fuzz_tests;

pub mod prelude {
    pub use crate::wrapped_sharing::{reconstruct, share, Reconstructor, Sharer};
}
