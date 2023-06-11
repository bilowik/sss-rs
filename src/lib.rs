#![doc = include_str!("../README.md")]

pub mod basic_sharing;
#[allow(dead_code)] 
mod geometry;
pub mod wrapped_sharing;


pub mod prelude {
    pub use crate::wrapped_sharing::{Sharer, Reconstructor, share, reconstruct};
}
