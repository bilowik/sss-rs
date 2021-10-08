use super::{fraction::Fraction, polynomial::Polynomial};
use crate::impl_binary_op;
use std::ops::{Add, Deref, Mul, Neg, Sub};

/// Represents a term in a polynomial function where the @co coefficient is multiplied by
/// 'x' ^ @degree.
#[derive(Default, Debug, Clone, Ord, PartialOrd, Eq, PartialEq)]
pub struct Term {
    degree: i32,  // The degree x is raised to
    co: Fraction, // The coefficient to the term
}

impl Term {
    /// Creates a new Term with a given fraction and degree
    pub fn new<T: Into<Fraction>>(co: T, degree: i32) -> Self {
        Term {
            co: co.into(),
            degree,
        }
    }

    pub fn get_degree(&self) -> i32 {
        self.degree
    }

    pub fn set_co(&mut self, co: Fraction) {
        self.co = co;
    }

    /// Return a reference to the coefficient of the term
    pub fn get_co(&self) -> &Fraction {
        &self.co
    }

    /// This is a consuming operation that attempts to add two terms that have the same degree.
    /// NOTE: If the two terms do not have the same degree, only an error will be returned and the
    /// values dropped.
    pub fn term_add_same_degree(mut self, rhs: Term) -> Result<Term, ()> {
        if self.get_degree() == rhs.get_degree() {
            self.co = self.co + rhs.co;
            Ok(self)
        } else {
            Err(())
        }
    }

    /// Consuming add operation that adds two Terms together and returns a polynomial. Since the
    /// two terms may not have the same degree, they would have to become a polynomial.
    pub fn term_add(mut self, rhs: Term) -> Polynomial {
        if self.degree == rhs.degree {
            self.co = self.co + rhs.co;
            self.into()
        } else {
            Polynomial::builder().with_term(self).with_term(rhs).build()
        }
    }

    /// Consuming sub operation that adds two Terms together and returns a polynomial. Since the
    /// two terms may not have the same degree, they would have to become a polynomial.
    pub fn term_sub(mut self, rhs: Term) -> Polynomial {
        if self.degree == rhs.degree {
            self.co = self.co - rhs.co;
            self.into()
        } else {
            Polynomial::builder()
                .with_term(self)
                .with_term(-rhs)
                .build()
        }
    }

    /// Consuming multiplication operation, returns a Term since the multiplication of two single
    /// terms will always return a single term thus not needing to be a polynomial
    pub fn term_mul(mut self, rhs: Term) -> Term {
        self.co = self.co * rhs.co;
        self.degree += rhs.degree;
        self
    }

    /// Consuming multiplication operation which scales the term by a given fraction.
    /// This is equivalent to @term_mul with the second term having a @degree of 0
    pub fn term_mul_fraction<T: Into<Fraction>>(mut self, rhs: T) -> Self {
        self.co = self.co * rhs.into();
        self
    }

    /// Consuming add operation that adds a polynomial to a given term.
    /// These are conveience operations that allow for:
    /// Polynomai + Term
    /// and
    /// Term + Polynomial
    /// to give a communitive poperty.
    pub fn term_add_poly(self, mut rhs: Polynomial) -> Polynomial {
        rhs.add_to_term(self);
        rhs
    }

    /// See @term_add_poly
    pub fn term_sub_poly(self, mut rhs: Polynomial) -> Polynomial {
        rhs.sub_to_term(self);
        rhs
    }

    /// See @term_add_poly
    pub fn term_mul_poly(self, rhs: Polynomial) -> Polynomial {
        rhs.mul_polynomial(self.into())
    }
}

impl_binary_op!(Term, Term, Add, add, term_add, Polynomial);
impl_binary_op!(Term, Term, Sub, sub, term_sub, Polynomial);
impl_binary_op!(Term, Term, Mul, mul, term_mul, Term);
impl_binary_op!(Term, Fraction, Mul, mul, term_mul_fraction, Term);
impl_binary_op!(Term, Polynomial, Add, add, term_add_poly, Polynomial);
impl_binary_op!(Term, Polynomial, Sub, sub, term_sub_poly, Polynomial);
impl_binary_op!(Term, Polynomial, Mul, mul, term_mul_poly, Polynomial);

impl Neg for Term {
    type Output = Self;
    fn neg(mut self) -> Self::Output {
        self.co = self.co.neg();
        self
    }
}

impl Neg for &Term {
    type Output = Term;

    fn neg(self) -> Self::Output {
        self.clone().neg()
    }
}

impl AsRef<Fraction> for Term {
    fn as_ref(&self) -> &Fraction {
        &self.co
    }
}

impl Deref for Term {
    type Target = Fraction;

    fn deref(&self) -> &Self::Target {
        &self.co
    }
}

impl std::fmt::Display for Term {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}x^{}", self.co, self.degree)
    }
}
