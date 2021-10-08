use super::fraction::Fraction;
use crate::{impl_binary_op, impl_binary_op_simple};
use std::ops::{Add, Sub};

#[allow(dead_code)]

/// A point structure that uses fractional values so that it can represent whole and non-whole
/// numbers without the need for truncating.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Default)]
pub struct Point {
    x: Fraction,
    y: Fraction,
}

impl Point {
    /// Creates a point from two values that impl Into<Fraction>
    pub fn new<T: Into<Fraction>, S: Into<Fraction>>(x: T, y: S) -> Self {
        Point {
            x: x.into(),
            y: y.into(),
        }
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

    pub fn scale(mut self, scalar: i64) -> Self {
        let scalar_frac = Fraction::new(scalar, 1);
        self.x = self.x * scalar_frac;
        self.y = self.y * scalar_frac;
        self
    }

    pub fn x(&self) -> Fraction {
        self.x
    }
    pub fn y(&self) -> Fraction {
        self.y
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

    #[test]
    fn add() {
        let p1 = Point::new(4, 2);
        let p2 = Point::new(3, 7);
        let p3 = Point::new(-8, 4);
        assert_eq!(p1 + p2, Point::new(7, 9));
        assert_eq!(p2 + p3, Point::new(-5, 11));
    }

    #[test]
    fn sub() {
        let p1 = Point::new(4, 2);
        let p2 = Point::new(3, 7);
        let p3 = Point::new(-8, 4);
        assert_eq!(p1 - p2, Point::new(1, -5));
        assert_eq!(p2 - p3, Point::new(11, 3));
    }

    #[test]
    fn scale() {
        let p1 = Point::new(4, 2);
        let p3 = Point::new(-8, 4);

        assert_eq!(p1.scale(3), Point::new(12, 6));
        assert_eq!(p3.scale(5), Point::new(-40, 20));
        assert_eq!(p1.scale(-1), Point::new(-4, -2));
    }
}
