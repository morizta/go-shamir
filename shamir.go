package shamir

import (
	"crypto/rand"
	"errors"
	"fmt"
)

const ShareOverhead = 1

var (
	ErrEmptySecret         = errors.New("cannot split empty secret")
	ErrInvalidParts        = errors.New("parts must be at least 2 and less than 256")
	ErrInvalidThreshold    = errors.New("threshold must be at least 2 and less than or equal to parts")
	ErrTooFewParts         = errors.New("less than two parts cannot be used to reconstruct the secret")
	ErrDifferentLengths    = errors.New("all parts must be the same length")
	ErrTooShort           = errors.New("parts must be at least two bytes")
	ErrDuplicatePart      = errors.New("duplicate part detected")
	ErrIntegrityCheckFailed = errors.New("integrity check failed")
	ErrInsufficientShares  = errors.New("insufficient shares provided")
)

func Split(secret []byte, parts, threshold int) ([][]byte, error) {
	if len(secret) == 0 {
		return nil, ErrEmptySecret
	}
	if parts < 2 || parts >= 256 {
		return nil, ErrInvalidParts
	}
	if threshold < 2 || threshold > parts {
		return nil, ErrInvalidThreshold
	}

	secretLen := len(secret)
	shares := make([][]byte, parts)
	
	coeffs := make([][]byte, threshold)
	coeffs[0] = make([]byte, secretLen)
	copy(coeffs[0], secret)
	
	for i := 1; i < threshold; i++ {
		coeffs[i] = make([]byte, secretLen)
		if _, err := rand.Read(coeffs[i]); err != nil {
			return nil, fmt.Errorf("failed to generate random coefficients: %w", err)
		}
	}

	for i := 0; i < parts; i++ {
		x := byte(i + 1)
		shares[i] = make([]byte, secretLen+ShareOverhead)
		shares[i][0] = x
		
		gfPolyEvalSlice(shares[i][1:], coeffs, x)
	}

	for i := range coeffs {
		if coeffs[i] != nil {
			secureZeroBytes(coeffs[i])
		}
	}

	return shares, nil
}

func Combine(parts [][]byte) ([]byte, error) {
	if len(parts) < 2 {
		return nil, ErrTooFewParts
	}

	if len(parts[0]) < 2 {
		return nil, ErrTooShort
	}

	secretLen := len(parts[0]) - ShareOverhead
	for i := 1; i < len(parts); i++ {
		if len(parts[i]) != len(parts[0]) {
			return nil, ErrDifferentLengths
		}
	}

	xCoords := make([]byte, len(parts))
	for i, part := range parts {
		xCoords[i] = part[0]
	}
	
	for i := 0; i < len(xCoords); i++ {
		for j := i + 1; j < len(xCoords); j++ {
			if xCoords[i] == xCoords[j] {
				return nil, ErrDuplicatePart
			}
		}
	}

	secret := make([]byte, secretLen)
	
	for byteIdx := 0; byteIdx < secretLen; byteIdx++ {
		yCoords := make([]byte, len(parts))
		for i, part := range parts {
			yCoords[i] = part[byteIdx+1]
		}
		
		secret[byteIdx] = lagrangeInterpolate(xCoords, yCoords, 0)
		
		secureZeroBytes(yCoords)
	}

	secureZeroBytes(xCoords)

	return secret, nil
}

func lagrangeInterpolate(xCoords, yCoords []byte, x byte) byte {
	var result byte
	n := len(xCoords)

	for i := 0; i < n; i++ {
		numerator := byte(1)
		denominator := byte(1)

		for j := 0; j < n; j++ {
			if i == j {
				continue
			}
			
			numerator = gfMult(numerator, gfAdd(x, xCoords[j]))
			denominator = gfMult(denominator, gfAdd(xCoords[i], xCoords[j]))
		}

		if denominator == 0 {
			continue
		}

		basis := gfDiv(numerator, denominator)
		term := gfMult(yCoords[i], basis)
		result = gfAdd(result, term)
	}

	return result
}

// lagrangeInterpolateSlice - vectorized version for potential future optimization
func lagrangeInterpolateSlice(dst []byte, xCoords []byte, yCoords [][]byte, x byte) {
	n := len(xCoords)
	if n == 0 || len(dst) == 0 {
		return
	}

	for i := range dst {
		dst[i] = 0
	}

	temp := make([]byte, len(dst))
	
	for i := 0; i < n; i++ {
		numerator := byte(1)
		denominator := byte(1)

		for j := 0; j < n; j++ {
			if i == j {
				continue
			}
			
			numerator = gfMult(numerator, gfAdd(x, xCoords[j]))
			denominator = gfMult(denominator, gfAdd(xCoords[i], xCoords[j]))
		}

		if denominator == 0 {
			continue
		}

		basis := gfDiv(numerator, denominator)
		gfMultSlice(temp, yCoords[i], basis)
		gfAddSlice(dst, dst, temp)
	}
}