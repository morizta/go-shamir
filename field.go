package shamir

import "unsafe"

// Galois Field GF(256) arithmetic operations for Shamir's Secret Sharing.
// This implementation uses pre-computed lookup tables for optimal performance.

// fieldTables holds the pre-computed exponential and logarithm tables for GF(256).
type fieldTables struct {
	exp [256]byte // Exponential table: exp[i] = generator^i
	log [256]byte // Logarithm table: log[exp[i]] = i
}

// Global field tables initialized at package load time.
var tables fieldTables

// init initializes the GF(256) lookup tables using the irreducible polynomial x^8 + x^4 + x^3 + x + 1.
func init() {
	buildFieldTables()
}

// buildFieldTables constructs the exponential and logarithm lookup tables for GF(256).
// Uses generator value 2 and irreducible polynomial 0x11d (x^8 + x^4 + x^3 + x + 1).
func buildFieldTables() {
	// Generator element (primitive root) for GF(256)
	generator := 1
	
	// Build exponential table: exp[i] = generator^i mod irreducible_polynomial
	for i := 0; i < 255; i++ {
		tables.exp[i] = byte(generator)
		tables.log[generator] = byte(i)
		
		// Multiply by 2 (shift left) and reduce if necessary
		generator <<= 1
		if generator&0x100 != 0 {
			generator ^= 0x11d // Reduce by irreducible polynomial
		}
	}
	
	// Handle special cases
	tables.exp[255] = tables.exp[0] // exp[255] = exp[0] = 1
	tables.log[0] = 255             // log[0] is undefined, use 255 as sentinel
}

// gfAdd performs addition in GF(256), which is simply XOR.
// This operation is its own inverse: a + b = a - b in GF(256).
// Addition and subtraction are identical in GF(256).
func gfAdd(a, b byte) byte {
	return a ^ b
}

// gfMult performs multiplication in GF(256) using lookup tables.
// Returns 0 if either operand is 0, otherwise uses exp/log tables for efficiency.
// This is the core multiplication operation for all GF(256) arithmetic.
func gfMult(a, b byte) byte {
	if a == 0 || b == 0 {
		return 0
	}
	
	// Multiplication in GF(256): a * b = exp[(log[a] + log[b]) mod 255]
	logSum := int(tables.log[a]) + int(tables.log[b])
	return tables.exp[logSum%255]
}

// gfDiv performs division in GF(256) using lookup tables.
// Division by zero panics as it's undefined in any field.
// Used primarily in Lagrange interpolation for secret reconstruction.
func gfDiv(a, b byte) byte {
	if b == 0 {
		panic("shamir: division by zero in GF(256)")
	}
	if a == 0 {
		return 0
	}
	
	// Division in GF(256): a / b = exp[(log[a] - log[b] + 255) mod 255]
	logDiff := int(tables.log[a]) - int(tables.log[b]) + 255
	return tables.exp[logDiff%255]
}

// gfInv computes the multiplicative inverse in GF(256).
// The inverse of 0 is undefined and will panic.
// Kept for mathematical completeness but not used in current implementation.
func gfInv(a byte) byte {
	if a == 0 {
		panic("shamir: inverse of zero is undefined in GF(256)")
	}
	
	// Inverse in GF(256): a^-1 = exp[(255 - log[a]) mod 255]
	return tables.exp[255-int(tables.log[a])]
}

// gfMultSlice performs vectorized multiplication of a slice by a scalar in GF(256).
// Optimizes for common cases (multiply by 0 or 1) and processes in 8-byte chunks where possible.
// This is the primary function used by the Shamir algorithm for polynomial operations.
func gfMultSlice(dst, src []byte, scalar byte) {
	if len(dst) != len(src) {
		panic("shamir: destination and source slices must have same length")
	}
	
	// Handle special cases for performance
	switch scalar {
	case 0:
		// Multiply by 0: result is all zeros
		for i := range dst {
			dst[i] = 0
		}
		return
	case 1:
		// Multiply by 1: result is identity
		copy(dst, src)
		return
	}
	
	// General case: use lookup table multiplication
	scalarLog := tables.log[scalar]
	
	// Process in chunks for better cache performance
	i := 0
	for i+8 <= len(src) {
		// Process 8 bytes at once
		for j := 0; j < 8; j++ {
			if src[i+j] == 0 {
				dst[i+j] = 0
			} else {
				logSum := int(tables.log[src[i+j]]) + int(scalarLog)
				dst[i+j] = tables.exp[logSum%255]
			}
		}
		i += 8
	}
	
	// Handle remaining bytes
	for i < len(src) {
		if src[i] == 0 {
			dst[i] = 0
		} else {
			logSum := int(tables.log[src[i]]) + int(scalarLog)
			dst[i] = tables.exp[logSum%255]
		}
		i++
	}
}

// gfAddSlice performs vectorized addition (XOR) of two slices in GF(256).
// Uses 64-bit operations for better performance on modern processors.
// This is a core operation used throughout the Shamir algorithm.
func gfAddSlice(dst, a, b []byte) {
	if len(dst) != len(a) || len(dst) != len(b) {
		panic("shamir: all slices must have the same length")
	}
	
	n := len(dst)
	i := 0
	
	// Process 8 bytes at a time using 64-bit XOR
	for i+8 <= n {
		*(*uint64)(unsafe.Pointer(&dst[i])) = 
			*(*uint64)(unsafe.Pointer(&a[i])) ^ 
			*(*uint64)(unsafe.Pointer(&b[i]))
		i += 8
	}
	
	// Handle remaining bytes
	for i < n {
		dst[i] = a[i] ^ b[i]
		i++
	}
}

// gfPolyEval evaluates a polynomial at a given point using Horner's method.
// Single-byte version kept for reference and simple use cases.
// The slice version (gfPolyEvalSlice) is used for performance in the main algorithm.
func gfPolyEval(coefficients []byte, x byte) byte {
	if len(coefficients) == 0 {
		return 0
	}
	
	// Horner's method: P(x) = a_n + x(a_(n-1) + x(a_(n-2) + ... + x*a_1))
	result := coefficients[len(coefficients)-1]
	for i := len(coefficients) - 2; i >= 0; i-- {
		result = gfMult(result, x) ^ coefficients[i]
	}
	
	return result
}

// gfPolyEvalSlice evaluates multiple polynomials simultaneously using Horner's method.
// This vectorized version processes all byte positions of the secret at once.
// Used for efficient share generation in the Split function.
func gfPolyEvalSlice(dst []byte, coefficients [][]byte, x byte) {
	if len(coefficients) == 0 || len(dst) == 0 {
		return
	}
	
	// Start with the highest degree coefficients
	copy(dst, coefficients[len(coefficients)-1])
	
	// Apply Horner's method: multiply by x and add next coefficient
	for i := len(coefficients) - 2; i >= 0; i-- {
		gfMultSlice(dst, dst, x)      // Multiply current result by x
		gfAddSlice(dst, dst, coefficients[i]) // Add coefficient for this degree
	}
}