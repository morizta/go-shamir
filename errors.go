package shamir

import "errors"

// Standard errors for Shamir Secret Sharing operations.
// These errors provide clear, actionable information about what went wrong.
var (
	// ErrEmptySecret indicates that an empty secret was provided for splitting.
	ErrEmptySecret = errors.New("shamir: cannot split empty secret")

	// ErrInvalidParts indicates that the number of parts is outside the valid range [2, 255].
	ErrInvalidParts = errors.New("shamir: parts must be between 2 and 255")

	// ErrInvalidThreshold indicates that the threshold is outside the valid range [2, parts].
	ErrInvalidThreshold = errors.New("shamir: threshold must be between 2 and parts")

	// ErrTooFewParts indicates that fewer than 2 shares were provided for reconstruction.
	ErrTooFewParts = errors.New("shamir: at least 2 shares required for reconstruction")

	// ErrDifferentLengths indicates that shares have different lengths, making reconstruction impossible.
	ErrDifferentLengths = errors.New("shamir: all shares must have the same length")

	// ErrTooShort indicates that shares are too short to contain valid data.
	ErrTooShort = errors.New("shamir: shares must be at least 2 bytes long")

	// ErrDuplicatePart indicates that duplicate shares (same x-coordinate) were provided.
	// This name is kept for compatibility with existing code.
	ErrDuplicatePart = errors.New("shamir: duplicate shares detected")

	// ErrIntegrityCheckFailed indicates that a share's integrity check (CRC32) failed.
	ErrIntegrityCheckFailed = errors.New("shamir: share integrity check failed")

	// ErrInsufficientShares indicates that fewer shares than required threshold were provided.
	ErrInsufficientShares = errors.New("shamir: insufficient shares for reconstruction")

	// ErrNilShares indicates that nil shares were provided.
	ErrNilShares = errors.New("shamir: shares cannot be nil")

	// ErrZeroThreshold indicates that a zero threshold was provided.
	ErrZeroThreshold = errors.New("shamir: threshold cannot be zero")
)

// ValidationError represents a validation error with context about what failed.
type ValidationError struct {
	Field   string // The field that failed validation
	Value   int    // The invalid value
	Message string // Human-readable error message
}

func (e *ValidationError) Error() string {
	return e.Message
}

// NewValidationError creates a new validation error with context.
func NewValidationError(field string, value int, message string) *ValidationError {
	return &ValidationError{
		Field:   field,
		Value:   value,
		Message: message,
	}
}