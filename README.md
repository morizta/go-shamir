# Go Shamir Secret Sharing

A high-performance, secure implementation of Shamir's Secret Sharing algorithm in Go. This library provides **16-30x better performance** than HashiCorp's Vault implementation while maintaining full API compatibility and adding enhanced security features.

## Features

- ✅ **100% API Compatible** with HashiCorp Vault's shamir package
- ⚡ **16-30x Performance Improvement** over existing implementations
- 🔒 **Enhanced Security Features** (memory zeroization, integrity checks, threshold enforcement)
- 🧮 **Optimized GF(256) Arithmetic** with lookup tables and vectorization
- 🔄 **Drop-in Replacement** for existing code
- 📦 **Zero Dependencies** (except for benchmarking against HashiCorp)

## Performance Comparison

| Operation | Our Implementation | HashiCorp Vault | Speedup |
|-----------|-------------------|-----------------|---------|
| Split (64KB) | **110.23 MB/s** | 6.61 MB/s | **16.7x** |
| Combine (64KB) | **31.20 MB/s** | 1.07 MB/s | **29.2x** |

## Installation

```bash
go get github.com/rizkytaufiq/go-shamir
```

## Quick Start

```go
package main

import (
    "fmt"
    "log"
    
    "github.com/rizkytaufiq/go-shamir"
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

### Basic Operations (HashiCorp Compatible)

#### Split
```go
func Split(secret []byte, parts, threshold int) ([][]byte, error)
```
Splits a secret into `parts` shares, requiring `threshold` shares to reconstruct.

**Parameters:**
- `secret`: The secret data to split
- `parts`: Total number of shares (2-255)
- `threshold`: Minimum shares needed for reconstruction (2 ≤ threshold ≤ parts)

**Returns:** Array of shares and error

#### Combine
```go
func Combine(parts [][]byte) ([]byte, error)
```
Reconstructs the original secret from shares.

**Parameters:**
- `parts`: Array of shares (must provide at least threshold number)

**Returns:** Reconstructed secret and error

### Enhanced Security API

#### SplitWithIntegrity
```go
func SplitWithIntegrity(secret []byte, parts, threshold int) ([][]byte, error)
```
Splits secret with CRC32 integrity checks added to each share.

#### CombineWithIntegrity
```go
func CombineWithIntegrity(parts [][]byte) ([]byte, error)
```
Combines shares with integrity validation.

#### SplitSecure
```go
func SplitSecure(secret []byte, parts, threshold int, enforceThreshold bool) ([][]byte, error)
```
Splits secret with automatic memory cleanup and optional threshold enforcement.

#### CombineSecure
```go
func CombineSecure(parts [][]byte, expectedThreshold int) ([]byte, error)
```
Combines shares with threshold validation and secure cleanup of input shares.

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
secret := []byte("confidential-data")
shares, _ := shamir.Split(secret, 7, 4)  // 7 shares, need 4
reconstructed, _ := shamir.Combine(shares[:4])
```

### With Integrity Checks
```go
secret := []byte("important-secret")
shares, _ := shamir.SplitWithIntegrity(secret, 5, 3)
reconstructed, _ := shamir.CombineWithIntegrity(shares[:3])
```

### Secure Operations
```go
secret := []byte("highly-sensitive")
shares, _ := shamir.SplitSecure(secret, 5, 3, true)
reconstructed, _ := shamir.CombineSecure(shares[:3], 3)
```

## Error Handling

The library provides detailed error types:

- `ErrEmptySecret`: Cannot split empty secret
- `ErrInvalidParts`: Parts must be 2-255
- `ErrInvalidThreshold`: Invalid threshold value  
- `ErrTooFewParts`: Insufficient shares for reconstruction
- `ErrDifferentLengths`: Shares have different lengths
- `ErrDuplicatePart`: Duplicate shares detected
- `ErrIntegrityCheckFailed`: Share corruption detected
- `ErrInsufficientShares`: Below required threshold

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
- Inspired by HashiCorp Vault's implementation
- Optimized for modern Go performance patterns