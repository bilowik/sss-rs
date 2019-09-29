use std::ops::Rem;
/// Trait for calculating modulo with negative numbers. Rem/Modulo operations move out the negative
/// number, but that is not always the needed output.
pub trait NaturalMod<T: Rem + Sized + Copy = Self>: Rem + Sized + Copy {
    type Output_: Sized + Copy;
    
    /// Computes the natural modulo of two given numbers.
    fn natural_mod(self, rhs: T) -> Self::Output_;
}



// Impl NaturalMod for all types that implement Rem<Self> and Add<Self> that output themselves
// TODO: Check if this is good practice.
/*
impl<T: Rem<T, Output=T> + Sized + Copy + Add<T, Output=T>> NaturalMod for T {
    type Output_ = Self;
    fn natural_mod(self, rhs: Self) -> Self {
    }
}
*/
fn floor(num: i64, div: i64) -> i64 {
    ((num as f64) / (div as f64)) as i64

}
fn ceiling(num: i64, div: i64) -> i64 {
    ((num.abs() + div - 1) / div) * num.signum()
}

impl NaturalMod for i64 {
    type Output_= i64;
    
    fn natural_mod(self, rhs: i64) -> i64 {
        let div = if self > 0 {
            floor(self, rhs)
        }
        else {
            ceiling(self, rhs)
        };

        (self - (div * rhs)).abs()
    }
}

#[cfg(test)]
mod tests {
    use super::NaturalMod;

    #[test]
    fn nmod() {

        let num = -7i64;
        let div = 3i64;
        let num2 = 7;
        assert_eq!(num.natural_mod(div), 2i64);
        assert_eq!(num2.natural_mod(div), 1i64);
        assert_eq!((-div).natural_mod(-num2), div);
    }
}

