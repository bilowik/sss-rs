use crate::{impl_binary_op, impl_binary_op_simple};
use lazy_static::lazy_static;
use num_traits::Pow;
use std::convert::{From, TryFrom};
use std::ops::{Add, Div, Mul, Neg, Rem, Sub};
/*
 * The Fraction struct is mainly used as the coefficients in the polynomial struct
 */

lazy_static! {
    pub static ref FRACTION_ONE: Fraction = Fraction::new(1, 1);
    pub static ref FRACTION_ZERO: Fraction = Fraction::new(0, 1);
}

/// A signed numerical value that is used to represent a fractional value or a whole value without
/// having to worry about decimals and truncating.
/// While both the @numerator and @denominator are signed values, only the numerator is allowed to
/// be negative. The denominator is signed to make mathematical operations easier and will
/// sometimes need to be negative during an operation but the sign will be moved to the numerator
/// automatically
#[derive(Debug, Copy, Clone, Ord, PartialOrd)]
pub struct Fraction {
    numerator: i64,
    // Numerator of the fraction, can be positive or negative depending on the sign of the
    // fraction
    denominator: i64,
    // Denominator of the fraction, will always be positive since the sign is only carried by the
    // numerator
}

impl Fraction {
    /// Creates a new fraction with the given numerator and denominator, which accepts any value
    /// that implements Into<i64>.
    /// @numerator: The numerator of the fraction
    /// @denominator: The denominator of the fraction
    pub fn new(numerator: i64, denominator: i64) -> Self {
        let frac = Fraction {
            numerator,
            denominator,
        };
        frac.reduce()
    }

    /// Returns a reference to the numerator of the fraction
    pub fn get_numerator(&self) -> i64 {
        self.numerator
    }

    /// Returns a reference to the denominator of the fraction
    pub fn get_denominator(&self) -> i64 {
        self.denominator
    }

    /// Consumes the fraction and returns the negation of it
    pub fn negate(mut self) -> Self {
        self.numerator = -self.numerator;
        self
    }

    /// Consuming add operation
    pub fn add_fraction(mut self, mut other: Fraction) -> Self {
        self.match_denominator(&mut other);
        self.numerator = self.numerator + other.numerator;
        self.reduce()
    }

    /// Consuming sub operation
    pub fn sub_fraction(self, other: Fraction) -> Self {
        self.add_fraction(-other)
    }

    /// Consuming multiplication operation
    pub fn mul_fraction(mut self, other: Fraction) -> Self {
        self.numerator = self.numerator * other.numerator;
        self.denominator = self.denominator * other.denominator;
        self.reduce()
    }

    /// Consuming division operation
    pub fn div_fraction(self, other: Fraction) -> Self {
        self.mul_fraction(other.flip()) // No reduction necessary since @mul_fraction already reduces
    }

    /// Consuming modulo operation
    pub fn mod_fraction(self, rhs: Fraction) -> Self {
        let mut div = &self / &rhs;

        if self.numerator.signum() == 1 {
            div = div.floor();
        } else {
            div = div.ceiling();
        }

        (self - (div * rhs)).abs()
    }

    /// Consuming add operation with the right hand side being a i64
    pub fn add_i64(mut self, rhs: i64) -> Self {
        self.numerator = self.numerator + (rhs * self.denominator);
        self.reduce()
    }

    /// Consuming sub operation with the right hand side being a i64
    pub fn sub_i64(self, rhs: i64) -> Self {
        self.add_i64(-rhs)
    }

    /// Consuming multiplication operation with the right hand side being a i64
    pub fn mul_i64(mut self, rhs: i64) -> Self {
        self.numerator = self.numerator * rhs;
        self.reduce()
    }

    /// Consuming division operation with the right hand side being a i64
    pub fn div_i64(mut self, rhs: i64) -> Self {
        self.denominator = self.denominator * rhs;
        self.reduce()
    }

    /// Consuming modulo operation with the right hand side being a i64
    pub fn mod_i64(self, rhs: i64) -> Self {
        let mut div = self / rhs;

        if self.numerator.signum() == 1 {
            div = div.floor();
        } else {
            div = div.ceiling();
        }

        (self - (div * rhs)).abs()
    }

    /// Consuming floor operation that "truncates" the fraction to a whole number
    pub fn floor(mut self) -> Self {
        self.numerator = self.numerator / self.denominator;
        self.denominator = 1;
        self
    }

    pub fn ceiling(mut self) -> Self {
        if !self.is_whole() {
            self.numerator = (&self.numerator / &self.denominator) + (1 * self.numerator.signum());
            self.denominator = 1;
            self
        } else {
            self
        }
    }

    /// Consuming absolute value operation, if the fraction is negative, it is made positive
    pub fn abs(mut self) -> Self {
        if self.numerator < 0 {
            self.numerator = -self.numerator;
        }
        self
    }

    /// Matches the denominator of @self and another given fraction, which is used to make addtion
    /// and subtraction operations possible.
    pub fn match_denominator(&mut self, other: &mut Fraction) {
        if self.denominator != other.denominator {
            let orig_denom = self.denominator;
            self.denominator = self.denominator * other.denominator;
            self.numerator = self.numerator * other.denominator;
            other.denominator = orig_denom * other.denominator;
            other.numerator = other.numerator * orig_denom;
        }
    }

    /// Reduces the fraction to the smallest possible numerator and denominator, which makes
    /// comparison operations much easier since we can assume that fractions that are equal will
    /// always have the same exact numerator and denominator
    fn reduce(mut self) -> Self {
        if self.numerator != 0 && self.denominator != 1 {
            let gcd = Self::gcd_i64(self.numerator, self.denominator);
            self.numerator = self.numerator / gcd;
            self.denominator = self.denominator / gcd;
        }

        if self.denominator < 0 {
            // The denominator should never have a negative sign, move it up to the numerator by
            // negating both the numerator and denominator
            self.denominator = -self.denominator;
            self.numerator = -self.numerator;
        }

        self
    }

    /// Consuming operation that flips the fraction
    pub fn flip(mut self) -> Self {
        if self.numerator != 0 {
            // If the numerator is 0, flipping it will make this fraction undefined. For my use
            // case, having 0/1 flip to 0/1 is desirable behavior.
            let temp = self.numerator;
            self.numerator = self.denominator;
            self.denominator = temp;
            if self.denominator < 0 {
                // Move up negative sign to numerator
                self.denominator = -self.denominator;
                self.numerator = -self.numerator;
            }
        }
        self
    }

    fn r_gcd_i64(a: i64, b: i64) -> i64 {
        if b != 0 {
            Self::r_gcd_i64(b, a % b)
        } else {
            a
        }
    }

    fn gcd_i64(a: i64, b: i64) -> i64 {
        Self::r_gcd_i64(a.abs(), b.abs())
    }

    /// Checks if the given fraction is a whole number, returns true if it is, false otherwise
    pub fn is_whole(&self) -> bool {
        if self.denominator == 1 {
            true
        } else if self.numerator == 0 {
            true
        } else {
            false
        }
    }
} // End impl Fraction

impl std::fmt::Display for Fraction {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        if self.is_whole() {
            write!(f, "{}", &self.numerator)
        } else {
            write!(f, "({}/{})", &self.numerator, &self.denominator)
        }
    }
}

impl Default for Fraction {
    fn default() -> Self {
        Fraction::new(0, 1)
    }
}

impl PartialEq for Fraction {
    fn eq(&self, other: &Self) -> bool {
        if self.numerator == 0 && other.numerator == 0 {
            true
        } else {
            (&self.numerator == &other.numerator) && (&self.denominator == &other.denominator)
        }
    }
}

impl Eq for Fraction {}

// See src/geometry/utils.rs for docs
// This implements those traits for every mixture of references and non-references to make
// operations much easier
impl_binary_op_simple!(Fraction, Add, add, add_fraction);
impl_binary_op_simple!(Fraction, Sub, sub, sub_fraction);
impl_binary_op_simple!(Fraction, Mul, mul, mul_fraction);
impl_binary_op_simple!(Fraction, Div, div, div_fraction);
impl_binary_op_simple!(Fraction, Rem, rem, mod_fraction);
impl_binary_op!(Fraction, i64, Add, add, add_i64, Fraction);
impl_binary_op!(Fraction, i64, Sub, sub, sub_i64, Fraction);
impl_binary_op!(Fraction, i64, Mul, mul, mul_i64, Fraction);
impl_binary_op!(Fraction, i64, Div, div, div_i64, Fraction);
impl_binary_op!(Fraction, i64, Rem, rem, mod_i64, Fraction);

impl Neg for Fraction {
    type Output = Fraction;

    fn neg(self) -> Self::Output {
        self.negate()
    }
}

impl Neg for &Fraction {
    type Output = Fraction;

    fn neg(self) -> Self::Output {
        self.clone().negate()
    }
}

use crate::utils::NaturalMod;
impl NaturalMod<i64> for Fraction {
    type Output_ = Fraction;
    fn natural_mod(self, rhs: i64) -> Fraction {
        (self % rhs + rhs) % rhs
    }
}

impl<T: Into<i64> + std::fmt::Debug> From<T> for Fraction {
    fn from(num: T) -> Self {
        let f = Fraction::new(num.into(), 1);
        return f;
    }
}

/// Attempts to convert a Fraction into a i64. Will return an error if the fraction is not a
/// whole number. If truncation is the goal, first call floor and then either TryFrom or
/// @get_numerator
impl TryFrom<Fraction> for i64 {
    type Error = String;

    fn try_from(fraction: Fraction) -> Result<Self, Self::Error> {
        if fraction.is_whole() {
            Ok(fraction.numerator)
        } else {
            Err(String::from(
                "Fraction isn't a whole number, denominator needs to be 1",
            ))
        }
    }
}

impl Pow<i32> for Fraction {
    type Output = Fraction;

    fn pow(self, rhs: i32) -> Fraction {
        let abs_rhs: u32 = rhs.abs() as u32;
        let mut lhs = if rhs < 0 { self.flip() } else { self };
        lhs.numerator = lhs.numerator.pow(abs_rhs);
        lhs.denominator = lhs.denominator.pow(abs_rhs);
        lhs.reduce()
    }
}

impl Pow<u32> for Fraction {
    type Output = Fraction;

    fn pow(mut self, pow: u32) -> Self {
        self.denominator = self.denominator.pow(pow);
        self.numerator = self.numerator.pow(pow);
        self.reduce()
    }
}

pub fn i64_pow_i32(lhs: i64, rhs: i32) -> Fraction {
    Fraction::new(lhs, 1).pow(rhs).reduce()
}

// Unit Tests
#[cfg(test)]
mod tests {
    use super::Fraction;
    use num_traits::Pow;

    #[test]
    fn add() {
        let frac = Fraction::new(3, 4);
        let frac2 = Fraction::new(6, 5);
        assert_eq!(frac + frac2, Fraction::new(39, 20));
    }

    #[test]
    fn sub() {
        let frac = Fraction::new(3, 14);
        let frac2 = Fraction::new(6, 7);
        assert_eq!(frac - frac2, Fraction::new(-9, 14));
    }

    #[test]
    fn mult() {
        let frac = Fraction::new(2, 4);
        let frac2 = Fraction::new(6, 3);
        assert_eq!(frac * frac2, Fraction::new(1, 1));
    }

    #[test]
    fn div() {
        let frac = Fraction::new(3, 4);
        let frac2 = Fraction::new(7, 2);
        assert_eq!(frac / frac2, Fraction::new(6, 28));
    }

    #[test]
    fn rem() {
        let frac = Fraction::new(3, 1);
        let frac2 = Fraction::new(8, 1);
        let frac3 = Fraction::new(7, 2);
        assert_eq!(frac2 % frac, Fraction::new(2, 1));
        assert_eq!(frac3 % frac, Fraction::new(1, 2));
    }

    #[test]
    fn abs() {
        let frac = Fraction::new(-3, 2);
        let frac2 = Fraction::new(3, 2);
        assert_eq!(frac.abs(), Fraction::new(3, 2));
        assert_eq!(frac2.abs(), Fraction::new(3, 2));
    }

    #[test]
    fn floor() {
        let frac = Fraction::new(7, 2);
        let frac2 = Fraction::new(10, 3);

        assert_eq!(frac.floor(), Fraction::new(3, 1));
        assert_eq!(frac2.floor(), Fraction::new(3, 1));
    }

    #[test]
    fn reduce() {
        let frac = Fraction::new(144, 12);
        let frac2 = Fraction::new(5, 125);
        let frac3 = Fraction::new(-36, 8);
        let frac4 = Fraction::new(3, -2);

        assert_eq!(frac, Fraction::new(12, 1));
        assert_eq!(frac2, Fraction::new(1, 25));
        assert_eq!(frac3, Fraction::new(-9, 2));
        assert_eq!(frac4, Fraction::new(-3, 2));
    }

    #[test]
    fn pow() {
        let frac = Fraction::new(3, 4);
        let frac2 = Fraction::new(9, 16);

        assert_eq!(frac.pow(2), frac2);
        assert_eq!(frac, frac.pow(1));
    }

    #[test]
    fn i64_ops() {
        let frac = Fraction::new(21, 1);
        let frac2 = Fraction::new(7, 1);
        let frac3 = Fraction::new(-21, 1);
        let big = 7i64;
        let big2 = 8i64;

        assert_eq!(&frac % frac2, &frac % big);
        assert_eq!(&frac3 % &big2, Fraction::new(3, 1));
    }
}
