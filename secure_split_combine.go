package shamir

import (
	"fmt"
)

func SplitWithIntegrity(secret []byte, parts, threshold int) ([][]byte, error) {
	shares, err := Split(secret, parts, threshold)
	if err != nil {
		return nil, err
	}

	secureShares := make([][]byte, len(shares))
	for i, share := range shares {
		secureShares[i] = addIntegrityCheck(share)
	}

	return secureShares, nil
}

func CombineWithIntegrity(parts [][]byte) ([]byte, error) {
	if len(parts) < 2 {
		return nil, ErrTooFewParts
	}

	validatedParts := make([][]byte, len(parts))
	for i, part := range parts {
		validated, err := validateIntegrityCheck(part)
		if err != nil {
			return nil, fmt.Errorf("share %d integrity check failed: %w", i, err)
		}
		validatedParts[i] = validated
	}

	return Combine(validatedParts)
}

func SplitSecure(secret []byte, parts, threshold int, enforceThreshold bool) ([][]byte, error) {
	if enforceThreshold && len(secret) > 0 {
		if parts < threshold {
			return nil, ErrInvalidThreshold
		}
	}

	shares, err := Split(secret, parts, threshold)
	if err != nil {
		return nil, err
	}

	defer secureZeroBytes(secret)

	return shares, nil
}

func CombineSecure(parts [][]byte, expectedThreshold int) ([]byte, error) {
	if expectedThreshold > 0 && len(parts) < expectedThreshold {
		return nil, ErrInsufficientShares
	}

	secret, err := Combine(parts)
	if err != nil {
		return nil, err
	}

	for _, part := range parts {
		secureOverwriteSlice(part)
	}

	return secret, nil
}