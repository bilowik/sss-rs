use std::ops::Rem;
use std::ops::Add;

/// Trait for calculating modulo with negative numbers. Rem/Modulo operations move out the negative
/// number, but that is not always the needed output.
pub trait NaturalMod<T: Rem + Sized + Copy = Self>: Rem + Sized + Copy {
    type Output_: Sized + Copy;
    
    /// Computes the natural modulo of two given numbers.
    fn natural_mod(self, rhs: T) -> Self::Output_;
}


// Impl NaturalMod for all types that implement Rem<Self> and Add<Self> that output themselves
// TODO: Check if this is good practice.
impl<T: Rem<T, Output=T> + Sized + Copy + Add<T, Output=T>> NaturalMod for T {
    type Output_ = Self;
    fn natural_mod(self, rhs: Self) -> Self {
        (self % rhs + rhs) % rhs
    }
}



