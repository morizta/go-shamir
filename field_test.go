package shamir

import (
	"bytes"
	"testing"
)

func TestGFArithmetic(t *testing.T) {
	t.Run("addition properties", func(t *testing.T) {
		// Test commutativity: a + b = b + a
		a, b := byte(123), byte(45)
		if gfAdd(a, b) != gfAdd(b, a) {
			t.Error("Addition is not commutative")
		}
		
		// Test identity: a + 0 = a
		if gfAdd(a, 0) != a {
			t.Error("Addition identity failed")
		}
		
		// Test inverse: a + a = 0
		if gfAdd(a, a) != 0 {
			t.Error("Addition inverse failed")
		}
	})

	t.Run("multiplication properties", func(t *testing.T) {
		// Test commutativity: a * b = b * a
		a, b := byte(123), byte(45)
		if gfMult(a, b) != gfMult(b, a) {
			t.Error("Multiplication is not commutative")
		}
		
		// Test identity: a * 1 = a
		if gfMult(a, 1) != a {
			t.Error("Multiplication identity failed")
		}
		
		// Test zero: a * 0 = 0
		if gfMult(a, 0) != 0 {
			t.Error("Multiplication by zero failed")
		}
	})

	t.Run("division properties", func(t *testing.T) {
		a, b := byte(123), byte(45)
		
		// Test division: (a * b) / b = a
		product := gfMult(a, b)
		if gfDiv(product, b) != a {
			t.Error("Division failed")
		}
		
		// Test division by 1: a / 1 = a
		if gfDiv(a, 1) != a {
			t.Error("Division by 1 failed")
		}
		
		// Test division of zero: 0 / a = 0
		if gfDiv(0, a) != 0 {
			t.Error("Division of zero failed")
		}
	})

	t.Run("inverse properties", func(t *testing.T) {
		a := byte(123)
		
		// Test inverse: a * inv(a) = 1
		inv := gfInv(a)
		if gfMult(a, inv) != 1 {
			t.Error("Multiplicative inverse failed")
		}
	})
}

func TestGFSliceOperations(t *testing.T) {
	t.Run("multiply slice", func(t *testing.T) {
		src := []byte{1, 2, 3, 4, 5}
		dst := make([]byte, len(src))
		scalar := byte(3)
		
		gfMultSlice(dst, src, scalar)
		
		// Verify each element
		for i := range src {
			expected := gfMult(src[i], scalar)
			if dst[i] != expected {
				t.Errorf("gfMultSlice[%d] = %d, want %d", i, dst[i], expected)
			}
		}
	})

	t.Run("multiply by zero", func(t *testing.T) {
		src := []byte{1, 2, 3, 4, 5}
		dst := make([]byte, len(src))
		
		gfMultSlice(dst, src, 0)
		
		for i, v := range dst {
			if v != 0 {
				t.Errorf("gfMultSlice by zero[%d] = %d, want 0", i, v)
			}
		}
	})

	t.Run("multiply by one", func(t *testing.T) {
		src := []byte{1, 2, 3, 4, 5}
		dst := make([]byte, len(src))
		
		gfMultSlice(dst, src, 1)
		
		if !bytes.Equal(dst, src) {
			t.Error("gfMultSlice by one should be identity")
		}
	})

	t.Run("add slices", func(t *testing.T) {
		a := []byte{1, 2, 3, 4, 5}
		b := []byte{5, 4, 3, 2, 1}
		dst := make([]byte, len(a))
		
		gfAddSlice(dst, a, b)
		
		for i := range a {
			expected := gfAdd(a[i], b[i])
			if dst[i] != expected {
				t.Errorf("gfAddSlice[%d] = %d, want %d", i, dst[i], expected)
			}
		}
	})
}

func TestPolynomialEvaluation(t *testing.T) {
	t.Run("constant polynomial", func(t *testing.T) {
		coeffs := []byte{42} // P(x) = 42
		x := byte(5)
		
		result := gfPolyEval(coeffs, x)
		if result != 42 {
			t.Errorf("constant polynomial evaluation = %d, want 42", result)
		}
	})

	t.Run("linear polynomial", func(t *testing.T) {
		coeffs := []byte{10, 3} // P(x) = 10 + 3x
		x := byte(2)
		
		// Expected: 10 + 3*2 = 10 + 6 = 10 XOR 6 in GF(256)
		expected := gfAdd(10, gfMult(3, 2))
		result := gfPolyEval(coeffs, x)
		
		if result != expected {
			t.Errorf("linear polynomial evaluation = %d, want %d", result, expected)
		}
	})

	t.Run("slice evaluation", func(t *testing.T) {
		// Multiple polynomials with same coefficients structure
		coeffs := [][]byte{
			{10, 20, 30}, // Constant terms
			{3, 6, 9},    // Linear coefficients
		}
		x := byte(2)
		dst := make([]byte, 3)
		
		gfPolyEvalSlice(dst, coeffs, x)
		
		// Verify each position independently
		for i := 0; i < 3; i++ {
			singleCoeffs := []byte{coeffs[0][i], coeffs[1][i]}
			expected := gfPolyEval(singleCoeffs, x)
			
			if dst[i] != expected {
				t.Errorf("slice evaluation[%d] = %d, want %d", i, dst[i], expected)
			}
		}
	})
}

func TestFieldTables(t *testing.T) {
	t.Run("table consistency", func(t *testing.T) {
		// Test that exp and log tables are inverses
		for i := 1; i < 256; i++ {
			b := byte(i)
			if tables.exp[tables.log[b]] != b {
				t.Errorf("table inconsistency at %d", i)
			}
		}
	})

	t.Run("generator properties", func(t *testing.T) {
		// Test that exp[0] = 1 (generator^0 = 1)
		if tables.exp[0] != 1 {
			t.Error("exp[0] should be 1")
		}
		
		// Test that log[1] = 0
		if tables.log[1] != 0 {
			t.Error("log[1] should be 0")
		}
	})
}

func BenchmarkGFOperations(b *testing.B) {
	a, c := byte(123), byte(45)
	
	b.Run("multiply", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_ = gfMult(a, c)
		}
	})
	
	b.Run("add", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_ = gfAdd(a, c)
		}
	})
	
	b.Run("divide", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_ = gfDiv(a, c)
		}
	})
}

func BenchmarkSliceOperations(b *testing.B) {
	src := make([]byte, 1024)
	dst := make([]byte, 1024)
	scalar := byte(123)
	
	for i := range src {
		src[i] = byte(i % 256)
	}
	
	b.Run("multiply_slice", func(b *testing.B) {
		b.SetBytes(1024)
		for i := 0; i < b.N; i++ {
			gfMultSlice(dst, src, scalar)
		}
	})
	
	b.Run("add_slice", func(b *testing.B) {
		b.SetBytes(1024)
		for i := 0; i < b.N; i++ {
			gfAddSlice(dst, src, dst)
		}
	})
}