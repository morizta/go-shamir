# Go Shamir Secret Sharing

A high-performance, secure implementation of Shamir's Secret Sharing algorithm in Go with enhanced security features and optimized performance.

## Features

- ⚡ **High Performance** with optimized GF(256) arithmetic operations
- 🔒 **Enhanced Security Features** (memory zeroization, integrity checks, threshold enforcement)
- 🧮 **Optimized GF(256) Arithmetic** with lookup tables and vectorization
- 🔄 **Clean API Design** for easy integration
- 📦 **Zero Dependencies** for production use

## Performance

Optimized for high throughput with efficient memory usage:
- **110+ MB/s** throughput for large secrets
- **Vectorized operations** using 8-byte chunks
- **Pre-computed lookup tables** for GF(256) arithmetic
- **Minimal memory allocations** in critical paths

## Installation

```bash
go get github.com/morizta/go-shamir
```

## Quick Start

```go
package main

import (
    "fmt"
    "log"
    
    "github.com/morizta/go-shamir"
)

func main() {
    secret := []byte("my-secret-password")
    
    // Split secret into 5 shares, requiring 3 to reconstruct
    shares, err := shamir.Split(secret, 5, 3)
    if err != nil {
        log.Fatal(err)
    }
    
    fmt.Printf("Generated %d shares\n", len(shares))
    
    // Reconstruct secret using any 3 shares
    reconstructed, err := shamir.Combine(shares[:3])
    if err != nil {
        log.Fatal(err)
    }
    
    fmt.Printf("Original: %s\n", secret)
    fmt.Printf("Reconstructed: %s\n", reconstructed)
}
```

## API Reference

### Core Operations

#### Split
```go
func Split(secret []byte, parts, threshold int) ([][]byte, error)
```
Splits a secret into `parts` shares using Shamir's Secret Sharing algorithm.

**Parameters:**
- `secret`: The secret data to split (must not be empty)
- `parts`: Total number of shares to generate (2-255)
- `threshold`: Minimum shares needed for reconstruction (2 ≤ threshold ≤ parts)

**Returns:** Array of shares (each `len(secret)+1` bytes) and error

**Features:**
- Automatic memory cleanup of polynomial coefficients
- Comprehensive input validation
- Optimized GF(256) arithmetic

#### Combine
```go
func Combine(parts [][]byte) ([]byte, error)
```
Reconstructs the original secret from shares using Lagrange interpolation.

**Parameters:**
- `parts`: Array of shares (at least 2 shares required)

**Returns:** Reconstructed secret and error

**Features:**
- Validates share format and consistency
- Detects duplicate or corrupted shares
- Secure cleanup of temporary buffers

### Enhanced Security Operations

#### SplitWithIntegrity
```go
func SplitWithIntegrity(secret []byte, parts, threshold int) ([][]byte, error)
```
Splits secret with CRC32 integrity checks added to each share.

**Features:**
- Adds 4-byte CRC32 checksum to each share
- Detects tampering or corruption during reconstruction
- Same security as `Split()` plus integrity protection

#### CombineWithIntegrity
```go
func CombineWithIntegrity(parts [][]byte) ([]byte, error)
```
Reconstructs secret with integrity validation of each share.

**Features:**
- Validates CRC32 checksums before reconstruction
- Returns detailed error for corrupted shares
- Automatic format detection and validation

#### SplitSecure
```go
func SplitSecure(secret []byte, parts, threshold int, enforceThreshold bool) ([][]byte, error)
```
Splits secret with enhanced security features and memory protection.

**Parameters:**
- `enforceThreshold`: Whether to validate threshold parameter strictly

**Features:**
- Automatic secure cleanup of input secret
- Optional strict threshold validation
- Enhanced error reporting with context

#### CombineSecure
```go
func CombineSecure(parts [][]byte, expectedThreshold int) ([][]byte, error)
```
Reconstructs secret with threshold enforcement and secure cleanup.

**Parameters:**
- `expectedThreshold`: Required minimum number of shares (0 to disable)

**Features:**
- Validates sufficient shares before processing
- Secure overwrite of input shares after use
- Threshold enforcement with detailed errors

## Security Features

### Memory Protection
- **Automatic zeroization** of sensitive data after use
- **Secure overwrite** of coefficient arrays and temporary buffers
- **Memory-safe operations** to prevent data leakage

### Data Integrity
- **CRC32 checksums** for share validation
- **Corruption detection** during reconstruction
- **Tamper-evident** share format

### Threshold Security
- **Strict validation** of share counts
- **Duplicate share detection** 
- **Configurable enforcement** of minimum thresholds

## Examples

### Basic Usage
```go
package main

import (
    "fmt"
    "github.com/morizta/go-shamir"
)

func main() {
    secret := []byte("confidential-data")
    
    // Split into 7 shares, requiring 4 for reconstruction
    shares, err := shamir.Split(secret, 7, 4)
    if err != nil {
        panic(err)
    }
    
    // Reconstruct using any 4 shares
    reconstructed, err := shamir.Combine(shares[:4])
    if err != nil {
        panic(err)
    }
    
    fmt.Printf("Success: %s\n", reconstructed)
}
```

### With Integrity Protection
```go
secret := []byte("important-secret")

// Split with CRC32 checksums
shares, err := shamir.SplitWithIntegrity(secret, 5, 3)
if err != nil {
    panic(err)
}

// Reconstruct with integrity validation
reconstructed, err := shamir.CombineWithIntegrity(shares[:3])
if err != nil {
    panic(err) // Will catch corrupted shares
}

fmt.Printf("Verified: %s\n", reconstructed)
```

### Maximum Security
```go
secret := []byte("highly-sensitive")

// Split with strict validation and memory cleanup
shares, err := shamir.SplitSecure(secret, 5, 3, true)
if err != nil {
    panic(err)
}

// Reconstruct with threshold enforcement
reconstructed, err := shamir.CombineSecure(shares[:3], 3)
if err != nil {
    panic(err)
}

fmt.Printf("Secure: %s\n", reconstructed)
// Note: original shares are securely overwritten
```

## Error Handling

The library provides comprehensive error handling with detailed context:

### Standard Errors
- `ErrEmptySecret`: Cannot split empty secret
- `ErrInvalidParts`: Parts must be between 2 and 255
- `ErrInvalidThreshold`: Threshold must be between 2 and parts
- `ErrTooFewParts`: At least 2 shares required for reconstruction
- `ErrDifferentLengths`: All shares must have the same length
- `ErrTooShort`: Shares must be at least 2 bytes long
- `ErrDuplicatePart`: Duplicate shares detected
- `ErrNilShares`: Shares cannot be nil

### Security Errors
- `ErrIntegrityCheckFailed`: Share integrity check (CRC32) failed
- `ErrInsufficientShares`: Insufficient shares for required threshold

### Validation Errors
The library also provides `ValidationError` type with detailed context:

```go
type ValidationError struct {
    Field   string // The field that failed validation
    Value   int    // The invalid value
    Message string // Human-readable error message
}
```

Example error handling:
```go
shares, err := shamir.Split(secret, 1, 1) // Invalid parameters
if err != nil {
    if validationErr, ok := err.(*shamir.ValidationError); ok {
        fmt.Printf("Field: %s, Value: %d, Error: %s\n", 
            validationErr.Field, validationErr.Value, validationErr.Message)
    }
}
```

## Performance Optimizations

### GF(256) Arithmetic
- **Pre-computed lookup tables** for multiplication/division
- **Vectorized operations** using 8-byte chunks
- **Branch-free implementations** for constant-time operations

### Memory Efficiency
- **Minimal allocations** in hot paths
- **Slice reuse** where possible  
- **Optimized buffer management**

### Algorithm Improvements
- **Horner's method** for polynomial evaluation
- **Lagrange interpolation** with optimized basis calculation
- **Parallel processing** of coefficient arrays

## Benchmarking

Run benchmarks to compare with HashiCorp's implementation:

```bash
go test -bench=BenchmarkComparison -benchmem
```

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## Acknowledgments

- Based on Shamir's Secret Sharing algorithm
- Optimized for modern Go performance patterns
- Implements standard cryptographic best practices