package shamir

import (
	"testing"
)

func TestValidateSplitParams(t *testing.T) {
	tests := []struct {
		name      string
		secret    []byte
		parts     int
		threshold int
		wantErr   error
	}{
		{
			name:      "valid parameters",
			secret:    []byte("test"),
			parts:     5,
			threshold: 3,
			wantErr:   nil,
		},
		{
			name:      "empty secret",
			secret:    []byte{},
			parts:     5,
			threshold: 3,
			wantErr:   ErrEmptySecret,
		},
		{
			name:      "parts too low",
			secret:    []byte("test"),
			parts:     1,
			threshold: 1,
			wantErr:   &ValidationError{},
		},
		{
			name:      "parts too high",
			secret:    []byte("test"),
			parts:     256,
			threshold: 3,
			wantErr:   &ValidationError{},
		},
		{
			name:      "threshold too low",
			secret:    []byte("test"),
			parts:     5,
			threshold: 1,
			wantErr:   &ValidationError{},
		},
		{
			name:      "threshold exceeds parts",
			secret:    []byte("test"),
			parts:     3,
			threshold: 5,
			wantErr:   &ValidationError{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateSplitParams(tt.secret, tt.parts, tt.threshold)
			
			if tt.wantErr == nil {
				if err != nil {
					t.Errorf("validateSplitParams() error = %v, wantErr %v", err, tt.wantErr)
				}
			} else {
				if err == nil {
					t.Errorf("validateSplitParams() error = %v, wantErr %v", err, tt.wantErr)
				}
			}
		})
	}
}

func TestValidateCombineParams(t *testing.T) {
	validShares := [][]byte{
		{1, 10, 20, 30},
		{2, 15, 25, 35},
		{3, 20, 30, 40},
	}

	tests := []struct {
		name    string
		shares  [][]byte
		wantErr error
	}{
		{
			name:    "valid shares",
			shares:  validShares,
			wantErr: nil,
		},
		{
			name:    "nil shares",
			shares:  nil,
			wantErr: ErrNilShares,
		},
		{
			name:    "too few shares",
			shares:  [][]byte{{1, 10}},
			wantErr: ErrTooFewParts,
		},
		{
			name:    "shares too short",
			shares:  [][]byte{{1}, {2}},
			wantErr: ErrTooShort,
		},
		{
			name: "different lengths",
			shares: [][]byte{
				{1, 10, 20},
				{2, 15, 25, 35},
			},
			wantErr: ErrDifferentLengths,
		},
		{
			name: "duplicate x-coordinates",
			shares: [][]byte{
				{1, 10, 20, 30},
				{1, 15, 25, 35},
			},
			wantErr: &ValidationError{},
		},
		{
			name: "nil share",
			shares: [][]byte{
				{1, 10, 20, 30},
				nil,
			},
			wantErr: &ValidationError{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateCombineParams(tt.shares)
			
			if tt.wantErr == nil {
				if err != nil {
					t.Errorf("validateCombineParams() error = %v, wantErr %v", err, tt.wantErr)
				}
			} else {
				if err == nil {
					t.Errorf("validateCombineParams() error = %v, wantErr %v", err, tt.wantErr)
				}
			}
		})
	}
}

func TestValidationError(t *testing.T) {
	err := NewValidationError("threshold", 10, "threshold too high")
	
	if err.Field != "threshold" {
		t.Errorf("ValidationError.Field = %v, want %v", err.Field, "threshold")
	}
	
	if err.Value != 10 {
		t.Errorf("ValidationError.Value = %v, want %v", err.Value, 10)
	}
	
	if err.Message != "threshold too high" {
		t.Errorf("ValidationError.Message = %v, want %v", err.Message, "threshold too high")
	}
	
	if err.Error() != "threshold too high" {
		t.Errorf("ValidationError.Error() = %v, want %v", err.Error(), "threshold too high")
	}
}