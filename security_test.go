package shamir

import (
	"bytes"
	"testing"
)

func TestSecurityFeatures(t *testing.T) {
	secret := []byte("test secret for security")

	t.Run("memory zeroization", func(t *testing.T) {
		testSlice := make([]byte, len(secret))
		copy(testSlice, secret)

		secureZeroBytes(testSlice)

		for i, b := range testSlice {
			if b != 0 {
				t.Errorf("byte at position %d not zeroed: %v", i, b)
			}
		}
	})

	t.Run("secure overwrite", func(t *testing.T) {
		testSlice := make([]byte, 64)
		for i := range testSlice {
			testSlice[i] = byte(i % 256)
		}

		secureOverwriteSlice(testSlice)

		for i, b := range testSlice {
			if b != 0 {
				t.Errorf("byte at position %d not overwritten: %v", i, b)
			}
		}
	})

	t.Run("integrity check", func(t *testing.T) {
		shares, err := Split(secret, 5, 3)
		if err != nil {
			t.Fatal(err)
		}

		shareWithIntegrity := addIntegrityCheck(shares[0])
		
		if len(shareWithIntegrity) != len(shares[0])+4 {
			t.Errorf("expected length %d, got %d", len(shares[0])+4, len(shareWithIntegrity))
		}

		validated, err := validateIntegrityCheck(shareWithIntegrity)
		if err != nil {
			t.Fatal(err)
		}

		if !bytes.Equal(validated, shares[0]) {
			t.Error("validated share doesn't match original")
		}

		corruptedShare := make([]byte, len(shareWithIntegrity))
		copy(corruptedShare, shareWithIntegrity)
		corruptedShare[1] ^= 0xFF

		_, err = validateIntegrityCheck(corruptedShare)
		if err != ErrIntegrityCheckFailed {
			t.Errorf("expected ErrIntegrityCheckFailed, got %v", err)
		}
	})
}

func TestSecureFunctions(t *testing.T) {
	secret := []byte("secure test secret")

	t.Run("split with integrity", func(t *testing.T) {
		shares, err := SplitWithIntegrity(secret, 5, 3)
		if err != nil {
			t.Fatal(err)
		}

		if len(shares) != 5 {
			t.Errorf("expected 5 shares, got %d", len(shares))
		}

		for _, share := range shares {
			if len(share) != len(secret)+ShareOverhead+4 {
				t.Errorf("expected share length %d, got %d", len(secret)+ShareOverhead+4, len(share))
			}
		}

		reconstructed, err := CombineWithIntegrity(shares[:3])
		if err != nil {
			t.Fatal(err)
		}

		if !bytes.Equal(reconstructed, secret) {
			t.Error("reconstruction failed with integrity checks")
		}
	})

	t.Run("threshold enforcement", func(t *testing.T) {
		shares, err := Split(secret, 5, 3)
		if err != nil {
			t.Fatal(err)
		}

		_, err = CombineSecure(shares[:2], 3)
		if err != ErrInsufficientShares {
			t.Errorf("expected ErrInsufficientShares, got %v", err)
		}

		reconstructed, err := CombineSecure(shares[:3], 3)
		if err != nil {
			t.Fatal(err)
		}

		if !bytes.Equal(reconstructed, secret) {
			t.Error("secure combine failed")
		}
	})
}