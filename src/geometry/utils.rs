/*
 * This macro is used to easily and quickly implement binary operations for structs for a mixture
 * of reference and non-reference values 
 *
 * $type is the type of the struct to be implmeneting on, the lhs
 * $type_rhs is rhs, the other operand
 * $op_trait is the std::ops trait to implement, only binary traits
 * $impl_func is the function that needs to be implemented for the op trait
 * $op_func must be a function: fn(self: $type, other: $type_rhs) -> $output
 * $output is the type output
 */
#[macro_export]
macro_rules! impl_binary_op {
    ($type:ty, $type_rhs:ty, $op_trait:ident, $impl_func:ident, $op_func:ident, $output:ty) => {
        impl $op_trait<$type_rhs> for $type {
            type Output = $output;

            fn $impl_func(self, rhs: $type_rhs) -> Self::Output {
                self.$op_func(rhs)
            }
        }
        
        impl $op_trait<&$type_rhs> for $type {
            type Output = $output;

            fn $impl_func(self, rhs: &$type_rhs) -> Self::Output {
                self.$op_func(rhs.clone())
            }
        }
        
        impl $op_trait<$type_rhs> for &$type {
            type Output = $output;

            fn $impl_func(self, rhs: $type_rhs) -> Self::Output {
                self.clone().$op_func(rhs)
            }
        }
        
        impl $op_trait<&$type_rhs> for &$type {
            type Output = $output;

            fn $impl_func(self, rhs: &$type_rhs) -> Self::Output {
                self.clone().$op_func(rhs.clone())
            }
        }
        
    }
}

// See the above macro for documentation
// This is a simplified wrapper that assumes that the lhs, rhs, and output of the operation are 
// all the same
#[macro_export]
macro_rules! impl_binary_op_simple {
    ($type:ty, $op_trait:ident, $impl_func:ident, $op_func:ident) => {
        impl_binary_op!($type, $type, $op_trait, $impl_func, $op_func, $type);
    }
}


