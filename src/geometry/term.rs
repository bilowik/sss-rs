use std::ops::{Add, Sub, Mul, Neg, Deref};
use super::{
    fraction::Fraction,
    polynomial::Polynomial,
};
use crate::impl_binary_op;


#[derive(Default, Debug, Clone, Ord, PartialOrd, Eq, PartialEq)]
pub struct Term {
    degree: usize, // The degree x is raised to
    co: Fraction, // The coefficient to the term
}

impl Term {
    pub fn new<T: Into<Fraction>>(co: T, degree: usize) -> Self {
        Term {co: co.into(), degree}
    }

    pub fn get_degree(&self) -> usize {
        self.degree
    }

    pub fn set_co(&mut self, co: Fraction) {
        self.co = co;
    }

    pub fn get_co<'a>(&'a self) -> &'a Fraction {
        &self.co
    }

    pub fn term_add_same_degree(mut self, rhs: Term) -> Result<Term, ()> {
        if self.get_degree() == rhs.get_degree() { 
            self.co = self.co + rhs.co;
            Ok(self)
        }
        else {
            Err(())
        }
    }

    pub fn term_add(mut self, rhs: Term) -> Polynomial {
        if self.degree == rhs.degree {
            self.co = self.co + rhs.co;
            self.into()
        }
        else {
            Polynomial::builder()
                .with_term(self)
                .with_term(rhs)
                .build()
        }
    }

    pub fn term_sub(mut self, rhs: Term) -> Polynomial {
        if self.degree == rhs.degree {
            self.co = self.co - rhs.co;
            self.into()
        }
        else {
            Polynomial::builder()
                .with_term(self)
                .with_term(-rhs)
                .build()
        }
    }

    pub fn term_mul(mut self, rhs: Term) -> Term {
        self.co = self.co * rhs.co;
        self.degree = self.degree + rhs.degree;
        self
    }


    pub fn term_mul_fraction<T: Into<Fraction>>(mut self, rhs: T) -> Self {
        self.co = self.co * rhs.into();
        self
    }

    pub fn term_add_poly(self, mut rhs: Polynomial) -> Polynomial {
        rhs.add_to_term(self);
        rhs
    }

    pub fn term_sub_poly(self, mut rhs: Polynomial) -> Polynomial {
        rhs.sub_to_term(self);
        rhs
    }

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





