use super::fraction::Fraction;
use super::point::Point;
use super::term::Term;
use crate::{impl_binary_op, impl_binary_op_simple};
use num_traits::Pow;
use std::ops::{Add, Deref, Mul, Neg, Sub};

/// A polynomial function that is made up of a Vec of @Term. It supports common operations done on
/// polynomials including finding the 'y' value with a given 'x' value.
#[derive(Debug, Clone)]
pub struct Polynomial {
    terms: Vec<Term>,
}

impl Polynomial {
    /// Creates an empty polynomial with no terms
    pub fn new() -> Self {
        Self { terms: vec![] }
    }

    /// From a given list of points, attempts to use Lagrange interpolation to generate the
    /// polynomial that runs through those points. Will return an error if there's not enough
    /// pointes to satisfy the @degree requested. If the degree is not to be known, it can be set
    /// to @points.len() - 1
    pub fn from_points(points: &Vec<Point>, degree: usize) -> Result<Self, Error> {
        let mut temp_polys: Vec<Polynomial> = Vec::with_capacity(degree + 1);
        let mut lagrange_polys: Vec<Polynomial> = Vec::with_capacity(degree + 1);

        if points.len() <= degree {
            return Err(Error::NotEnoughPoints {
                points_given: points.len(),
                points_needed: degree + 1,
                degree,
            });
        }

        for j in 0..=degree {
            for m in 0..=degree {
                if m != j {
                    temp_polys.push(
                        Polynomial::builder()
                            .with(1, 1)
                            .with(-(points[m].x()), 0)
                            .scale_by((points[j].x() - points[m].x()).flip())
                            .build(),
                    );
                }
            }
            // Get the product of the polynomials and scale by the y value
            lagrange_polys.push(vec_product(&temp_polys).scale(points[j].y().clone()));
            temp_polys.clear();
        }

        // Now sum up lagrange polys
        Ok(vec_sum(&lagrange_polys))
    }

    /// Returns a PolynomialBuilder struct that provides a builder design pattern.
    pub fn builder() -> PolynomialBuilder {
        PolynomialBuilder::new()
    }

    /// Gets the degree of the polynomial
    pub fn get_degree(&self) -> i32 {
        match self.terms.last() {
            Some(term) => {
                // There is a last term, return its degree
                term.get_degree()
            }
            None => {
                // No terms existed in the list, return 0 for the degree
                0
            }
        }
    }

    fn bin_search_terms(&self, degree: i32) -> Result<usize, usize> {
        self.terms
            .as_slice()
            .binary_search_by(|val: &Term| val.get_degree().cmp(&degree))
    }

    // TODO: Refactor the names of these functions, remove the 'to' since it seems unusual and
    // unhelpful
    // TODO: Make this match its sister subtraction fucntion, the discrepency doesn't make any
    // sense
    /// Adds a term to the polynomial
    pub fn add_to_term(&mut self, term: Term) {
        self.set_term(
            self.get_term(term.get_degree())
                .term_add_same_degree(term)
                .unwrap(),
        );
    }

    /// Subs aterm from the polynomial
    pub fn sub_to_term(&mut self, term: Term) {
        self.set_terms(&term - self.get_term(term.get_degree()));
    }

    /// Sets the term with degree @term.get_degree() to @term
    pub fn set_term(&mut self, term: Term) {
        match self.bin_search_terms(term.get_degree()) {
            Ok(index) => {
                // It was found, so overwrite it
                self.terms[index] = term;
            }
            Err(index) => {
                self.terms.insert(index, term);
            }
        }
    }

    /// Iterates through @poly's terms and sets each of @self's terms to those from @poly
    pub fn set_terms(&mut self, poly: Polynomial) {
        for term in poly {
            self.set_term(term);
        }
    }

    /// Returns a copy of the term with the given degree, or creates a new zero coefficient term
    /// and returns it. This term is not added into the polynomial
    pub fn get_term(&self, degree: i32) -> Term {
        match self.bin_search_terms(degree) {
            Ok(index) => {
                // term exists
                self.terms[index].clone()
            }
            Err(_) => {
                // term doesn't exist, return a 0 term
                Term::new(0, degree)
            }
        }
    }

    /// Adds together two polynomials, consuming both and returning the sum
    pub fn add_polynomial(mut self, rhs: Self) -> Self {
        for term in rhs {
            self.add_to_term(term);
        }
        self
    }

    /// Subtracts one polynomial from the other, consuming both and returning the difference
    pub fn sub_polynomial(mut self, rhs: Self) -> Self {
        for term in rhs {
            self.sub_to_term(term);
        }
        self
    }

    /// Multiplies together two polynomials, consuming both and returning the product
    pub fn mul_polynomial(self, rhs: Self) -> Self {
        let mut prod = Self::default();

        for lterm in self {
            for rterm in rhs.clone() {
                prod.add_to_term(&lterm * rterm);
            }
        }
        prod
    }

    /// Scales the polynomial with the given @scalar. Each term gets multiplied by @scalar with no
    /// impact on the terms' degree
    pub fn scale<T: Into<Fraction>>(mut self, scalar: T) -> Self {
        let scalar = scalar.into();
        for index in 0..self.terms.len() {
            self.terms[index as usize] = &self.terms[index as usize] * &scalar;
        }
        self
    }

    /// Negates the entire polynomial, meaning each term has its sign flipped
    pub fn negate(self) -> Self {
        self.scale(-1)
    }

    /// Get the corresponding 'y' value to the given 'x' value
    pub fn get_y_value(&self, x_val: Fraction) -> Fraction {
        let mut frac = Fraction::new(0, 1);

        for term_index in 0..self.terms.len() {
            let curr_term = &self.terms[term_index];
            frac = frac + ((x_val.pow(curr_term.get_degree())) * curr_term.get_co());
        }

        frac
    }
}

impl Neg for Polynomial {
    type Output = Self;
    fn neg(self) -> Self::Output {
        self.negate()
    }
}

impl Neg for &Polynomial {
    type Output = Polynomial;
    fn neg(self) -> Self::Output {
        self.clone().negate()
    }
}

impl_binary_op_simple!(Polynomial, Add, add, add_polynomial);
impl_binary_op_simple!(Polynomial, Sub, sub, sub_polynomial);
impl_binary_op_simple!(Polynomial, Mul, mul, mul_polynomial);

/// Creates an iterator that iterates through the terms of the polynomial
impl IntoIterator for Polynomial {
    type Item = Term;
    type IntoIter = std::vec::IntoIter<Self::Item>;

    fn into_iter(self) -> Self::IntoIter {
        self.terms.into_iter()
    }
}

impl std::fmt::Display for Polynomial {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let mut out: String = String::from("");

        for i in 0..self.terms.len() {
            let curr_term = &self.terms[i];

            if curr_term.deref() != &Fraction::from(0) {
                out.push_str(format!("{}", self.terms[i]).as_ref());
                if i < self.terms.len() - 1 {
                    // Up until the last coefficient, append a + sign between them
                    out.push_str(" + ");
                }
            }
        }

        if &out[..] == "" {
            out.push_str("0x^0");
        }

        write!(f, "{}", out)
    }
}

impl Default for Polynomial {
    fn default() -> Self {
        Self::new()
    }
}

impl From<Term> for Polynomial {
    fn from(term: Term) -> Self {
        Polynomial::builder().with_term(term).build()
    }
}

impl PartialEq for Polynomial {
    fn eq(&self, other: &Self) -> bool {
        if self.get_degree() != other.get_degree() {
            return false;
        }

        // SO they must have the same degree
        for degree in 0..self.get_degree() {
            if self.get_term(degree) != other.get_term(degree) {
                return false;
            }
        }

        true
    }
}

impl Eq for Polynomial {}

pub struct PolynomialBuilder {
    polynomial: Polynomial,
}

impl PolynomialBuilder {
    pub fn new() -> Self {
        PolynomialBuilder {
            polynomial: Default::default(),
        }
    }
    pub fn with_term(mut self, term: Term) -> Self {
        self.polynomial.set_term(term);
        self
    }
    pub fn with<T: Into<Fraction>>(self, val: T, degree: i32) -> Self {
        self.with_term(Term::new(val.into(), degree))
    }
    pub fn add_to(mut self, poly: Polynomial) -> Self {
        self.polynomial = self.polynomial.add_polynomial(poly);
        self
    }
    pub fn sub_to_term(mut self, poly: Polynomial) -> Self {
        self.polynomial = self.polynomial.sub_polynomial(poly);
        self
    }
    pub fn mul_by(mut self, poly: Polynomial) -> Self {
        self.polynomial = self.polynomial.mul_polynomial(poly);
        self
    }
    pub fn scale_by<T: Into<Fraction>>(mut self, scalar: T) -> Self {
        self.polynomial = self.polynomial.scale(scalar);
        self
    }
    pub fn build(&mut self) -> Polynomial {
        std::mem::replace(&mut self.polynomial, Default::default())
    }
}

#[derive(Debug, Clone)]
pub enum Error {
    NotEnoughPoints {
        points_given: usize,
        points_needed: usize,
        degree: usize,
    },
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Error::NotEnoughPoints {
                points_given,
                points_needed,
                degree,
            } => {
                write!(
                    f,
                    "Not enough points to generate a polynomial of degree {}. 
                       Need {} points, only given {}.",
                    degree, points_needed, points_given
                )
            }
        }
    }
}

impl std::error::Error for Error {}

// Used to cleanup code in from_points
fn vec_product(vec: &Vec<Polynomial>) -> Polynomial {
    if vec.len() == 0 {
        return Default::default();
    }

    let mut product = vec[0].clone();
    for index in 1..vec.len() {
        product = product * &vec[index];
    }
    product
}

// Used to cleanup code in from_points
fn vec_sum(vec: &Vec<Polynomial>) -> Polynomial {
    let mut sum = Polynomial::default();
    for index in 0..vec.len() {
        sum = sum + &vec[index];
    }
    sum
}

#[cfg(test)]
mod test {
    use super::Fraction;
    use super::Point;
    use super::Polynomial;
    use super::Term;

    #[test]
    fn display() {
        let poly = Polynomial::builder().with(4, 0).with(3, 1).build();
        let poly2 = Polynomial::default();

        let poly3 = Polynomial::builder()
            .with(Fraction::new(3, 2), 0)
            .with(Fraction::new(8, 3), 1)
            .build();

        assert_eq!("4x^0 + 3x^1", poly.to_string());

        assert_eq!("0x^0", format!("{}", poly2));

        assert_eq!("(3/2)x^0 + (8/3)x^1", poly3.to_string());
    }

    #[test]
    fn add() {
        let poly1 = Polynomial::builder()
            .with(4, 0)
            .with(2, 1)
            .add_to(Polynomial::builder().with(2, 0).with(5, 1).build())
            .build();
        let poly2 = Polynomial::builder().with(6, 0).with(7, 1).build();

        assert_eq!(poly1, poly2);
    }

    #[test]
    fn from_points() {
        let points = vec![Point::new(1, 2), Point::new(2, 3)];

        let poly = Polynomial::from_points(&points, 1).unwrap();
        let poly2 = Polynomial::builder().with(1, 0).with(1, 1).build();

        assert_eq!(poly, poly2);
    }

    #[test]
    fn from_points_second() {
        let points2 = vec![Point::new(0, 0), Point::new(1, 1), Point::new(2, 4)];
        let poly3 = Polynomial::from_points(&points2, 2).unwrap();
        let poly4 = Polynomial::builder().with(1, 2).build();

        assert_eq!(poly3, poly4);
    }

    #[test]
    fn from_points_many() {
        let points = vec![
            Point::new(0, 0),
            Point::new(5, 8),
            Point::new(2, 3),
            Point::new(8, 14),
        ];

        let poly = Polynomial::from_points(&points, 3).unwrap();
        let poly2 = Polynomial::builder()
            .with(Fraction::new(263, 180), 1)
            .with(Fraction::new(1, 72), 2)
            .with(Fraction::new(1, 360), 3)
            .build();

        assert_eq!(poly, poly2);
    }

    /*
    #[test]
    fn from_points_fracs() {
        let points = vec![
           Point::new(Fraction::new(3/2)
    */

    #[test]
    fn builder_and_scale() {
        let poly = Polynomial::builder()
            .with(5, 0)
            .with(4, 1)
            .with(1, 2)
            .scale_by(3)
            .build();
        let poly2 = Polynomial {
            terms: vec![Term::new(15, 0), Term::new(12, 1), Term::new(3, 2)],
        };

        assert_eq!(poly, poly2);
    }

    #[test]
    fn zero_poly_ops() {
        let poly = Polynomial::default();

        let poly2 = Polynomial::builder()
            .with(4, 0)
            .with(4, 1)
            .with(1, 2)
            .build();

        assert_eq!(&poly * &poly2, Polynomial::default());
        assert_eq!(&poly + &poly2, poly2.clone());
        assert_eq!(&poly2 - &poly, poly2.clone());
        assert_eq!(&poly, &-&poly);
    }

    #[test]
    fn negate() {
        let poly = Polynomial::builder()
            .with(-4, 0)
            .with(4, 1)
            .with(1, 2)
            .build();

        let poly2 = Polynomial::builder()
            .with(4, 0)
            .with(-4, 1)
            .with(-1, 2)
            .build();

        assert_eq!(&poly, &-&poly2);
        assert_eq!(&-&poly, &poly2);
        assert_eq!(&(-(-&poly)), &poly);
    }

    #[test]
    fn multiplication() {
        let poly = Polynomial::builder().with(2, 0).with(1, 1).build();

        let poly2 = Polynomial::builder()
            .with(4, 0)
            .with(4, 1)
            .with(1, 2)
            .build();
        let poly3 = Polynomial::builder()
            .with(8, 0)
            .with(12, 1)
            .with(6, 2)
            .with(1, 3)
            .build();

        assert_eq!(&(&poly * &poly), &poly2);
        assert_eq!(&(&poly * &poly * &poly), &poly3);
    }

    #[test]
    fn get_y_value() {
        let poly = Polynomial::builder().with(2, 0).with(1, 1).build();
        let poly2 = Polynomial::builder()
            .with(-4, 0)
            .with(-2, 1)
            .with(1, 2)
            .build();
        let poly3 = Polynomial::default();

        assert_eq!(poly.get_y_value(0.into()), 2.into());
        assert_eq!(poly.get_y_value(1.into()), 3.into());
        assert_eq!(poly2.get_y_value(2.into()), (-4).into());
        assert_eq!(poly3.get_y_value(10000.into()), 0.into());
    }

    #[test]
    fn negative_degree_test() {
        let poly = Polynomial::builder().with(1, -1).with(3, -2).build();

        assert_eq!(poly.get_y_value(5.into()), Fraction::new(8, 25));
    }
}
