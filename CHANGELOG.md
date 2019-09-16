## sss-rs 0.1.1 09/16/2019
 - Fixed Rust stable compilation error regarding enum variants on type aliases
 	- In the Display impl for the Error enum, its variants were referenced as Self:: instead of Error::
	  which caused compilation issues on Rust's current stable version 1.36.0


## sss-rs 0.1.0 09/15/2019
 - Initial version 
