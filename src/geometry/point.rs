use num_bigint_dig::BigInt;
use super::fraction::Fraction;
use crate::{impl_binary_op, impl_binary_op_simple};
use std::ops::{Add, Sub};

#[allow(dead_code, unused_imports)]




#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Point {
    x: Fraction,
    y: Fraction,
}


impl Point {

    pub fn new<T: Into<Fraction>, S: Into<Fraction>>(x: T, y: S) -> Self {
        Point { x: x.into(), y: y.into() }
    }

    pub fn add_point(mut self, rhs: Point) -> Self {
        self.x = self.x + rhs.x;
        self.y = self.y + rhs.y;
        self
    }

    pub fn sub_point(mut self, rhs: Point) -> Self {
        self.x = self.x - rhs.x;
        self.y = self.y - rhs.y;
        self
    }

    pub fn scale<T: Into<BigInt>>(mut self, scalar: T) -> Self {
        let scalar_frac = Fraction::new(scalar, 1);
        self.x = self.x * &scalar_frac;
        self.y = self.y * &scalar_frac;
        self
    }

    pub fn x<'a>(&'a self) -> &'a Fraction {
        &self.x
    }
    pub fn y<'a>(&'a self) -> &'a Fraction {
        &self.y
    }
}

impl_binary_op_simple!(Point, Add, add, add_point);
impl_binary_op_simple!(Point, Sub, sub, sub_point);


impl std::fmt::Display for Point {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "({},{})", &self.x, &self.y)
    }
}


#[cfg(test)]
mod tests {
   use super::Point;
   use pretty_assertions::assert_eq;

   #[test]
    fn add() {
        let p1 = Point::new(4, 2);
        let p2 = Point::new(3, 7);
        let p3 = Point::new(-8, 4);
        assert_eq!(p1 + &p2, Point::new(7, 9));
        assert_eq!(p2 + p3, Point::new(-5, 11));
    }

    #[test]
    fn sub() {
        let p1 = Point::new(4, 2);
        let p2 = Point::new(3, 7);
        let p3 = Point::new(-8, 4);
        assert_eq!(p1 - &p2, Point::new(1, -5));
        assert_eq!(p2 - p3, Point::new(11, 3));
    }

    #[test]
    fn scale() {
        let p1 = Point::new(4, 2);
        let p3 = Point::new(-8, 4);

        assert_eq!(p1.clone().scale(3), Point::new(12, 6));
        assert_eq!(p3.scale(5), Point::new(-40, 20));
        assert_eq!(p1.scale(-1), Point::new(-4, -2));
    }
}


