use galois_2p8::*;
use lazy_static::*;
use std::ops::{Add, Deref, Div, Mul, Sub};

lazy_static! {
    // The field to use for all the finite field arithmetic
    static ref FIELD: PrimitivePolynomialField =
        PrimitivePolynomialField::new(field::PRIMITIVES[0]).unwrap();
}

/// A wrapper around u8, used to implement arithmetic operations over a finite field
#[derive(Clone, Copy, Debug)]
pub struct Coeff(pub u8);

impl Deref for Coeff {
    type Target = u8;

    fn deref(&self) -> &u8 {
        &self.0
    }
}

impl Into<Coeff> for u8 {
    fn into(self) -> Coeff {
        Coeff(self)
    }
}

impl Add for Coeff {
    type Output = Coeff;
    fn add(self, rhs: Coeff) -> Coeff {
        Coeff(FIELD.add(*self, *rhs))
    }
}
impl Sub for Coeff {
    type Output = Coeff;
    fn sub(self, rhs: Coeff) -> Coeff {
        Coeff(FIELD.sub(*self, *rhs))
    }
}
impl Mul for Coeff {
    type Output = Coeff;
    fn mul(self, rhs: Coeff) -> Coeff {
        Coeff(FIELD.mult(*self, *rhs))
    }
}
impl Div for Coeff {
    type Output = Coeff;
    fn div(self, rhs: Coeff) -> Coeff {
        Coeff(FIELD.div(*self, *rhs))
    }
}

#[derive(Clone, Debug)]
pub struct GaloisPolynomial {
    coeffs: Vec<Coeff>,
}

impl GaloisPolynomial {
    /// Constructs a polynomail with no coefficients
    pub fn new() -> GaloisPolynomial {
        Self {
            coeffs: Vec::with_capacity(8),
        }
    }

    /// Copies the values from the coeffs slice into a vec as the coefficients of the polynomial
    /// The coefficients go from left to right, where x^0 at coeffs[0]
    pub fn from_slice(coeffs: &[u8]) -> GaloisPolynomial {
        Self {
            coeffs: coeffs.into_iter().map(|val| Coeff(*val)).collect(),
        }
    }

    /// Constructs a polynomial with the coefficients in the vec
    /// The coefficients go from left to right, where x^0 at coeffs[0]
    pub fn with_vec(coeffs: Vec<u8>) -> GaloisPolynomial {
        Self {
            coeffs: coeffs.into_iter().map(|val| Coeff(val)).collect(),
        }
    }

    /// Reconstructs a polynomial from the given points
    pub fn from_points(points: &[(u8, u8)]) -> GaloisPolynomial {
        let mut lagrange_polys = Vec::with_capacity(points.len());
        let mut temp_polys = Vec::with_capacity(points.len());

        let points: Vec<(_, _)> = points
            .into_iter()
            .map(|(x, y)| (Coeff(*x), Coeff(*y)))
            .collect();
        for i in 0..points.len() {
            for j in 0..points.len() {
                if i != j {
                    let mut curr = Self::with_vec(Vec::with_capacity(points.len()));
                    curr.set_coeff(Coeff(1), 1);
                    curr.set_coeff(points[j].0, 0);
                    curr = curr.scale_divide(points[i].0 - points[j].0);
                    temp_polys.push(curr);
                }
            }

            // Now multiply all the current poly's together and push it onto langrange_polys
            let initial_val = temp_polys[0].clone();
            lagrange_polys.push(
                temp_polys
                    .clone()
                    .into_iter()
                    .skip(1)
                    .fold(initial_val, |acc, poly| acc.mult(poly))
                    .scale(points[i].1),
            );
            temp_polys.clear();
        }

        let initial_val = lagrange_polys[0].clone();
        let sum = lagrange_polys
            .into_iter()
            .skip(1)
            .fold(initial_val, |acc, poly| acc.add(poly));
        sum
    }

    /// Calculates the y intercept of the polynomial formed by the given points
    /// This is more efficient than completely reconstructing the polynomial and then calling
    /// $get_y_val if you do not plan to use the reconstructed polynomial after getting the y
    /// intercept.
    pub fn get_y_intercept_from_points(points: &[(u8, u8)]) -> u8 {
        let mut acc = Coeff(0);
        let points: Vec<(_, _)> = points
            .into_iter()
            .map(|(x, y)| (Coeff(*x), Coeff(*y)))
            .collect();
        for i in 0..points.len() {
            let mut curr = Coeff(1);
            for j in 0..points.len() {
                if i != j {
                    curr = curr * (points[j].0 / (points[i].0 - points[j].0));
                }
            }
            acc = acc + (curr * points[i].1);
        }
        *acc
    }

    /// Sets the coefficient at the given index to the given co
    pub fn set_coeff(&mut self, co: Coeff, index: usize) {
        if self.coeffs.len() < index + 1 {
            self.coeffs.resize_with(index + 1, || Coeff(0));
        }

        self.coeffs[index] = co;
    }

    /// Returns a copy of the coefficient at the specified index
    pub fn get_coeff(&self, index: usize) -> Coeff {
        if index + 1 < self.coeffs.len() {
            self.coeffs[index]
        } else {
            Coeff(0)
        }
    }

    /// Scales the polynomial by multiplying by the co
    pub fn scale(mut self, co: Coeff) -> Self {
        for i in 0..self.coeffs.len() {
            self.coeffs[i] = self.coeffs[i] * co;
        }
        self
    }

    /// Scales the polynomial by dividing by the co
    pub fn scale_divide(mut self, co: Coeff) -> Self {
        for i in 0..self.coeffs.len() {
            self.set_coeff(self.get_coeff(i) / co, i);
        }
        self
    }

    /// Multiplies two polynomial together
    pub fn mult(self, rhs: Self) -> Self {
        let mut prod = Self::with_vec(Vec::with_capacity(self.coeffs.len() + rhs.coeffs.len()));
        for lhs_coeff in self.coeffs {
            for (i, rhs_coeff) in rhs.coeffs.clone().into_iter().enumerate() {
                prod.set_coeff(prod.get_coeff(i) + (rhs_coeff * lhs_coeff), i);
            }
        }
        prod
    }

    /// Adds two polynomials together
    pub fn add(mut self, rhs: Self) -> Self {
        for (i, coeff) in rhs.coeffs.into_iter().enumerate() {
            self.set_coeff(self.get_coeff(i) + coeff, i);
        }
        self
    }

    /// Calculates the y-value given an x-value
    pub fn get_y_value(&self, x_val: u8) -> u8 {
        let x_val_coeff = Coeff(x_val);
        // This needs to be reversed since we are assuming the y-intercept in the field is the
        // left-most byte rather than the right-most.
        *(&self.coeffs)
            .into_iter()
            .rev()
            .fold(Coeff(0u8), |acc, co| (acc * x_val_coeff) + *co)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn get_y_intercept_gf() {
        let poly = GaloisPolynomial::with_vec(vec![5, 128, 8]);
        assert_eq!(5, poly.get_y_value(0));
    }

    #[test]
    fn from_points_gf() {
        let poly = GaloisPolynomial::with_vec(vec![5, 128, 8]);
        let x_vals = vec![1, 2, 4];
        let points: Vec<(_, _)> = x_vals
            .into_iter()
            .map(|x| (x, poly.get_y_value(x)))
            .collect();
        let poly_2 = GaloisPolynomial::from_points(points.as_slice());
        let y0 = GaloisPolynomial::get_y_intercept_from_points(points.as_slice());

        assert_eq!(poly.get_y_value(0), poly_2.get_y_value(0));
        assert_eq!(poly.get_y_value(0), y0);
    }
}
