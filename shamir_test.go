package shamir

import (
	"bytes"
	"fmt"
	"testing"
)

func TestSplitCombine(t *testing.T) {
	tests := []struct {
		name      string
		secret    []byte
		parts     int
		threshold int
	}{
		{"small secret", []byte("hello"), 5, 3},
		{"medium secret", []byte("this is a longer secret message"), 7, 4},
		{"binary data", []byte{0x00, 0xFF, 0x42, 0xAA, 0x55}, 3, 2},
		{"minimum threshold", []byte("test"), 3, 2},
		{"maximum parts", []byte("test"), 255, 128},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			shares, err := Split(tt.secret, tt.parts, tt.threshold)
			if err != nil {
				t.Fatalf("Split failed: %v", err)
			}

			if len(shares) != tt.parts {
				t.Fatalf("expected %d shares, got %d", tt.parts, len(shares))
			}

			for i, share := range shares {
				if len(share) != len(tt.secret)+ShareOverhead {
					t.Fatalf("share %d has wrong length: expected %d, got %d", 
						i, len(tt.secret)+ShareOverhead, len(share))
				}
			}

			reconstructed, err := Combine(shares[:tt.threshold])
			if err != nil {
				t.Fatalf("Combine failed: %v", err)
			}

			if !bytes.Equal(reconstructed, tt.secret) {
				t.Fatalf("reconstruction failed: expected %v, got %v", tt.secret, reconstructed)
			}

			if tt.threshold > 2 {
				reconstructed2, err := Combine(shares[1:tt.threshold+1])
				if err != nil {
					t.Fatalf("Combine with different shares failed: %v", err)
				}

				if !bytes.Equal(reconstructed2, tt.secret) {
					t.Fatalf("reconstruction with different shares failed")
				}
			}
		})
	}
}

func TestLargeSecrets(t *testing.T) {
	secrets := [][]byte{
		[]byte("hello world"),
		[]byte("test secret"),
		[]byte{0x00, 0xFF, 0x42, 0xAA, 0x55, 0x33, 0x77},
		make([]byte, 1024),
	}

	for i, secret := range secrets {
		if len(secret) == 1024 {
			for j := range secret {
				secret[j] = byte(j % 256)
			}
		}

		t.Run(fmt.Sprintf("secret_%d", i), func(t *testing.T) {
			shares, err := Split(secret, 5, 3)
			if err != nil {
				t.Fatalf("Split failed: %v", err)
			}

			reconstructed, err := Combine(shares[:3])
			if err != nil {
				t.Fatalf("Combine failed: %v", err)
			}

			if !bytes.Equal(reconstructed, secret) {
				t.Fatalf("Reconstruction failed")
			}

			// Test with different share combinations
			reconstructed2, err := Combine(shares[1:4])
			if err != nil {
				t.Fatalf("Combine with different shares failed: %v", err)
			}

			if !bytes.Equal(reconstructed2, secret) {
				t.Fatalf("Reconstruction with different shares failed")
			}
		})
	}
}

func TestErrorCases(t *testing.T) {
	t.Run("empty secret", func(t *testing.T) {
		_, err := Split([]byte{}, 5, 3)
		if err != ErrEmptySecret {
			t.Fatalf("expected ErrEmptySecret, got %v", err)
		}
	})

	t.Run("invalid parts", func(t *testing.T) {
		secret := []byte("test")
		
		_, err := Split(secret, 1, 1)
		if err == nil {
			t.Fatalf("expected error for parts=1, got nil")
		}

		_, err = Split(secret, 256, 128)
		if err == nil {
			t.Fatalf("expected error for parts=256, got nil")
		}
	})

	t.Run("invalid threshold", func(t *testing.T) {
		secret := []byte("test")
		
		_, err := Split(secret, 5, 1)
		if err == nil {
			t.Fatalf("expected error for threshold=1, got nil")
		}

		_, err = Split(secret, 5, 6)
		if err == nil {
			t.Fatalf("expected error for threshold>parts, got nil")
		}
	})

	t.Run("too few parts for combine", func(t *testing.T) {
		shares := [][]byte{
			{1, 42},
		}
		
		_, err := Combine(shares)
		if err != ErrTooFewParts {
			t.Fatalf("expected ErrTooFewParts, got %v", err)
		}
	})

	t.Run("different lengths", func(t *testing.T) {
		shares := [][]byte{
			{1, 42, 24},
			{2, 33},
		}
		
		_, err := Combine(shares)
		if err != ErrDifferentLengths {
			t.Fatalf("expected ErrDifferentLengths, got %v", err)
		}
	})

	t.Run("too short", func(t *testing.T) {
		shares := [][]byte{
			{1},
			{2},
		}
		
		_, err := Combine(shares)
		if err != ErrTooShort {
			t.Fatalf("expected ErrTooShort, got %v", err)
		}
	})

	t.Run("duplicate parts", func(t *testing.T) {
		shares := [][]byte{
			{1, 42, 24},
			{1, 33, 55},
		}
		
		_, err := Combine(shares)
		if err == nil {
			t.Fatalf("expected error for duplicate parts, got nil")
		}
	})
}

func TestGFOperations(t *testing.T) {
	t.Run("multiplication", func(t *testing.T) {
		if gfMult(0, 123) != 0 {
			t.Error("0 * anything should be 0")
		}
		if gfMult(123, 0) != 0 {
			t.Error("anything * 0 should be 0")
		}
		if gfMult(1, 123) != 123 {
			t.Error("1 * x should be x")
		}
		if gfMult(123, 1) != 123 {
			t.Error("x * 1 should be x")
		}
	})

	t.Run("addition", func(t *testing.T) {
		if gfAdd(0, 123) != 123 {
			t.Error("0 + x should be x")
		}
		if gfAdd(123, 0) != 123 {
			t.Error("x + 0 should be x")
		}
		if gfAdd(123, 123) != 0 {
			t.Error("x + x should be 0 in GF(256)")
		}
	})

	t.Run("slice operations", func(t *testing.T) {
		a := []byte{1, 2, 3, 4}
		b := []byte{5, 6, 7, 8}
		dst := make([]byte, 4)

		gfAddSlice(dst, a, b)
		expected := []byte{4, 4, 4, 12}
		if !bytes.Equal(dst, expected) {
			t.Errorf("gfAddSlice failed: expected %v, got %v", expected, dst)
		}

		gfMultSlice(dst, a, 2)
		expected = []byte{2, 4, 6, 8}
		if !bytes.Equal(dst, expected) {
			t.Errorf("gfMultSlice failed: expected %v, got %v", expected, dst)
		}
	})
}