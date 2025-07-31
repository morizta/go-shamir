package shamir

// validateSplitParams validates the parameters for splitting a secret.
// Returns appropriate errors for invalid inputs with detailed context.
func validateSplitParams(secret []byte, parts, threshold int) error {
	if len(secret) == 0 {
		return ErrEmptySecret
	}
	
	if parts < 2 {
		return NewValidationError("parts", parts, "shamir: parts must be at least 2")
	}
	
	if parts > 255 {
		return NewValidationError("parts", parts, "shamir: parts must not exceed 255")
	}
	
	if threshold < 2 {
		return NewValidationError("threshold", threshold, "shamir: threshold must be at least 2")
	}
	
	if threshold > parts {
		return NewValidationError("threshold", threshold, "shamir: threshold cannot exceed parts")
	}
	
	return nil
}

// validateCombineParams validates the parameters for combining shares.
// Performs comprehensive validation of share format and consistency.
func validateCombineParams(shares [][]byte) error {
	if shares == nil {
		return ErrNilShares
	}
	
	if len(shares) < 2 {
		return ErrTooFewParts
	}
	
	if len(shares[0]) < 2 {
		return ErrTooShort
	}
	
	// Validate all shares have the same length
	expectedLength := len(shares[0])
	for i, share := range shares {
		if share == nil {
			return NewValidationError("share", i, "shamir: share cannot be nil")
		}
		
		if len(share) != expectedLength {
			return ErrDifferentLengths
		}
	}
	
	// Check for duplicate x-coordinates (share identifiers)
	xCoords := make(map[byte]bool, len(shares))
	for i, share := range shares {
		xCoord := share[0]
		if xCoords[xCoord] {
			return NewValidationError("share", i, "shamir: duplicate share identifier detected")
		}
		xCoords[xCoord] = true
	}
	
	return nil
}

// validateSecureParams validates parameters for secure operations.
func validateSecureParams(shares [][]byte, expectedThreshold int) error {
	if err := validateCombineParams(shares); err != nil {
		return err
	}
	
	if expectedThreshold > 0 && len(shares) < expectedThreshold {
		return NewValidationError("shares", len(shares), 
			"shamir: insufficient shares for required threshold")
	}
	
	return nil
}