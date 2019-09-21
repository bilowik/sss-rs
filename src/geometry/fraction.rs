use num_bigint_dig::{BigInt, Sign};
use lazy_static::lazy_static;
use std::ops::{Add, Sub, Mul, Div, Neg, Rem};
use std::convert::{TryFrom, From};
use crate::{impl_binary_op_simple, impl_binary_op};
use num_traits::{Pow, One, Zero, sign::Signed};

/*
 * The Fraction struct is mainly used as the coefficients in the polynomial struct
 */



lazy_static! {
    pub static ref BIGINT_ZERO: BigInt = BigInt::from(0);
    pub static ref BIGINT_ONE: BigInt = BigInt::from(1);
    pub static ref FRACTION_ONE: Fraction = Fraction::new(1, 1);
    pub static ref FRACTION_ZERO: Fraction = Fraction::new(0, 1);
}


/// A signed numerical value that is used to represent a fractional value or a whole value without 
/// having to worry about decimals and truncating.
/// While both the @numerator and @denominator are signed values, only the numerator is allowed to
/// be negative. The denominator is signed to make mathematical operations easier and will
/// sometimes need to be negative during an operation but the sign will be moved to the numerator
/// automatically
#[derive(Debug, Clone, Ord, PartialOrd)]
pub struct Fraction {
    numerator: BigInt, 
    // Numerator of the fraction, can be positive or negative depending on the sign of the
    // fraction
    
    
    denominator: BigInt,
    // Denominator of the fraction, will always be positive since the sign is only carried by the 
    // numerator
}


impl Fraction {

    /// Creates a new fraction with the given numerator and denominator, which accepts any value
    /// that implements Into<BigInt>.
    /// @numerator: The numerator of the fraction
    /// @denominator: The denominator of the fraction
    pub fn new<S: Into<BigInt>, T: Into<BigInt>>(numerator: S, denominator: T) -> Self {
        let frac = Fraction {
            numerator: numerator.into(), 
            denominator: denominator.into()
        };
        frac.reduce()
    }
   
    /// Returns a reference to the numerator of the fraction
    pub fn get_numerator<'a>(&'a self) -> &'a BigInt {
        &self.numerator
    }
    
    /// Returns a reference to the denominator of the fraction
    pub fn get_denominator<'a>(&'a self) -> &'a BigInt {
        &self.denominator
    }

    /// Consumes the fraction and returns the negation of it
    pub fn negate(mut self) -> Self {
        self.numerator = -&self.numerator;
        self
    }

    /// Consuming add operation
    pub fn add_fraction(mut self, mut other: Fraction) -> Self {
        self.match_denominator(&mut other); 
        self.numerator = &self.numerator + &other.numerator;
        self.reduce()
    }

    /// Consuming sub operation
    pub fn sub_fraction(self, other: Fraction) -> Self {
        self.add_fraction(-other)
    }

    /// Consuming multiplication operation
    pub fn mul_fraction(mut self, other: Fraction) -> Self {
        self.numerator = &self.numerator * &other.numerator;
        self.denominator = &self.denominator * &other.denominator;
        self.reduce()
    }

    /// Consuming division operation
    pub fn div_fraction(self, other: Fraction) -> Self {
        self.mul_fraction(other.flip()) // No reduction necessary since @mul_fraction already reduces
    }

   
    /// Consuming modulo operation
    pub fn mod_fraction(self, rhs: Fraction) -> Self {
        let mut div = &self / &rhs;
        div = div.floor(); // Floor to remove denominator, which brings @div to a whole number
        (&self - &(&div * &rhs)).abs()
        
    }

    /// Consuming add operation with the right hand side being a BigInt
    pub fn add_bigint(mut self, rhs: BigInt) -> Self {
        self.numerator = &self.numerator + (rhs * &self.denominator);
        self.reduce()
    }

    /// Consuming sub operation with the right hand side being a BigInt
    pub fn sub_bigint(self, rhs: BigInt) -> Self {
        self.add_bigint(-rhs)
    }

    /// Consuming multiplication operation with the right hand side being a BigInt
    pub fn mul_bigint(mut self, rhs: BigInt) -> Self {
        self.numerator = &self.numerator * rhs;
        self.reduce()
    }

    /// Consuming division operation with the right hand side being a BigInt
    pub fn div_bigint(mut self, rhs: BigInt) -> Self {
        self.denominator = &self.denominator * rhs;
        self.reduce()
    }

    
    /// Consuming modulo operation with the right hand side being a BigInt
    pub fn mod_bigint(self, rhs: BigInt) -> Self {
        let mut div = &self / &rhs;
        div = div.floor();
        (&self - &(&div * &rhs)).abs()
    }

    /// Calculates modulo when self may be negative. Separate from normal modulo since it relies on
    /// it.
    pub fn natural_mod_bigint(self, rhs: BigInt) -> Self {
        // Equivalent to: ((self % rhs) + rhs) % rhs
        (self.mod_bigint(rhs.clone()) + &rhs).mod_bigint(rhs.clone())
    }


    /* The performance boost is very negligible due to the need for cloning the lhs in this
     * scenario, since get_co() returns a reference which cannot be consumed by this function.
    /// A self consuming modulo operation which avoids cloning the rhs operand
    /// This is in testing, may not improve performance
    pub fn mod_bigint_ref_optimized(self, rhs: &BigInt) -> Self {
        if self.numerator.sign() != Sign::Minus {
            let mut div = &self / rhs;
            div = div.floor();
            (&self - &(&div * rhs)).abs()
        }
        else {
            // The bigint_dig library doesn't handle modulo in the way we need it to with negative
            // numbers, so this gives us the output that we need.
            (-(-self % rhs) + rhs)
        }

    }
    */
     

    /// Consuming floor operation that "truncates" the fraction to a whole number
    pub fn floor(mut self) -> Self {
        self.numerator = &self.numerator / &self.denominator;
        self.denominator = BIGINT_ONE.clone();
        self
    }

    /// Consuming absolute value operation, if the fraction is negative, it is made positive
    pub fn abs(self) -> Self {
        match self.numerator.sign() {
            Sign::Minus => self.negate(),
            _ => self,
        }
    }

    /// Matches the denominator of @self and another given fraction, which is used to make addtion
    /// and subtraction operations possible.
    pub fn match_denominator(&mut self, other: &mut Fraction) {
        if self.denominator != other.denominator {
           let orig_denom = self.denominator.clone();
           self.denominator = &self.denominator * &other.denominator;
           self.numerator = &self.numerator * &other.denominator;
           other.denominator = &orig_denom * &other.denominator;
           other.numerator = &other.numerator * &orig_denom;
        }
    }

   
    /// Reduces the fraction to the smallest possible numerator and denominator, which makes
    /// comparison operations much easier since we can assume that fractions that are equal will
    /// always have the same exact numerator and denominator
    fn reduce(mut self) -> Self {
        if !self.numerator.is_zero() && !self.denominator.is_one() {
            let gcd = Self::gcd_bigint(&self.numerator, &self.denominator);
            self.numerator = &self.numerator / &gcd;
            self.denominator = &self.denominator / &gcd;
        }

        if self.denominator.sign() == Sign::Minus {
            // The denominator should never have a negative sign, move it up to the numerator by
            // negating both the numerator and denominator
            self.denominator = -&self.denominator;
            self.numerator = -&self.numerator;
        }

        if &self.numerator == &self.denominator {
            self.numerator = BigInt::from(1);
            self.denominator = BigInt::from(1);
        }


        self
    }

    /// Consuming operation that flips the fraction
    pub fn flip(mut self) -> Self {
        if !self.numerator.is_zero() { 
            // If the numerator is 0, flipping it will make this fraction undefined. For my use
            // case, having 0/1 flip to 0/1 is desirable behavior.
            let temp = self.numerator.clone();
            self.numerator = self.denominator.clone();
            self.denominator = temp;
            if self.denominator.sign() == Sign::Minus {
                // Move up negative sign to numerator
                self.denominator = self.denominator.neg();
                self.numerator = self.numerator.neg();
            }
        }
        self
    }

    fn r_gcd_bigint(a: &BigInt, b: &BigInt) -> BigInt {
        if !b.is_zero() {
            Self::r_gcd_bigint(b, &(a % b))
        }
        else {
            a.clone()
        }


    }

    fn gcd_bigint(a: &BigInt, b: &BigInt) -> BigInt {
        let ac = match a.sign() {
            Sign::Minus => -a.clone(),
            _ => a.clone(),
        };
        let bc = match b.sign() {
            Sign::Minus => -b.clone(),
            _ => b.clone(),
        };
        Self::r_gcd_bigint(&ac, &bc) 

        /*
        while ac != bc {
            dbg!(&ac, &bc);
            if ac > bc {
                ac = &ac - &bc;
            }
            else {
                bc = &bc - &ac;
            }
        }
        ac
        */
    }

    /// Checks if the given fraction is a whole number, returns true if it is, false otherwise
    pub fn is_whole(&self) -> bool {
        if self.denominator.is_one() {
            true
        }
        else if self.numerator.is_zero() {
            true
        }
        else {
            false
        }
    }


    /// Consuming exponential operation, raising the fraction to the given power.
    pub fn pow(mut self, pow: usize) -> Self {
        self.denominator = self.denominator.pow(pow);
        self.numerator = self.numerator.pow(pow);
        self.reduce()
    }




} // End impl Fraction


impl std::fmt::Display for Fraction {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        if self.is_whole() {
            write!(f, "{}", &self.numerator)
        }
        else {
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
        if self.numerator.is_zero() && other.numerator.is_zero() {
            true
        }
        else {
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
impl_binary_op!(Fraction, BigInt, Add, add, add_bigint, Fraction);
impl_binary_op!(Fraction, BigInt, Sub, sub, sub_bigint, Fraction);
impl_binary_op!(Fraction, BigInt, Mul, mul, mul_bigint, Fraction);
impl_binary_op!(Fraction, BigInt, Div, div, div_bigint, Fraction);
impl_binary_op!(Fraction, BigInt, Rem, rem, natural_mod_bigint, Fraction);


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



impl<T: Into<BigInt> + std::fmt::Debug> From<T> for Fraction {
    fn from(num: T) -> Self {
        let f = Fraction::new(num.into(), BigInt::from(1));
        return f;

    }
}





/// Attempts to convert a Fraction into a BigInt. Will return an error if the fraction is not a
/// whole number. If truncation is the goal, first call floor and then either TryFrom or
/// @get_numerator
impl TryFrom<Fraction> for BigInt {
    type Error = String;

    fn try_from(fraction: Fraction) -> Result<Self, Self::Error> {
        if fraction.numerator.is_one() {
            Ok(fraction.numerator)
        }
        else {
            Err(String::from("Fraction isn't a whole number, denominator needs to be 1"))
        }
    }
}


// Unit Tests
#[cfg(test)]
mod tests {
    use super::Fraction;

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
        assert_eq!(&frac2 % &frac, Fraction::new(2, 1));
        assert_eq!(&frac3 % &frac, Fraction::new(1, 2));
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

        assert_eq!(&frac.clone().pow(2usize), &frac2);
        assert_eq!(&frac, &frac.clone().pow(1usize));
    }

    #[test]
    fn bigint_ops() {
        use num_bigint_dig::BigInt;
        let frac = Fraction::new(21, 1);
        let frac2 = Fraction::new(7, 1);
        let big = BigInt::from(7usize);

        assert_eq!(&frac % frac2, &frac % big);


    }
        


}



