package main

import (
	"fmt"
	"time"

	"github.com/rizkytaufiq/go-shamir"
	hashiShamir "github.com/hashicorp/vault/shamir"
)

func main() {
	fmt.Println("=== Performance Comparison Example ===")
	
	sizes := []int{1024, 4096, 16384, 65536}
	
	for _, size := range sizes {
		fmt.Printf("\n--- Testing with %d byte secret ---\n", size)
		
		// Generate test data
		secret := make([]byte, size)
		for i := range secret {
			secret[i] = byte(i % 256)
		}
		
		// Benchmark our implementation
		start := time.Now()
		iterations := 1000
		
		for i := 0; i < iterations; i++ {
			shares, err := shamir.Split(secret, 5, 3)
			if err != nil {
				panic(err)
			}
			_, err = shamir.Combine(shares[:3])
			if err != nil {
				panic(err)
			}
		}
		
		ourTime := time.Since(start)
		ourThroughput := float64(size*iterations*2) / ourTime.Seconds() / 1024 / 1024
		
		// Benchmark HashiCorp implementation
		start = time.Now()
		
		for i := 0; i < iterations; i++ {
			shares, err := hashiShamir.Split(secret, 5, 3)
			if err != nil {
				panic(err)
			}
			_, err = hashiShamir.Combine(shares[:3])
			if err != nil {
				panic(err)
			}
		}
		
		hashiTime := time.Since(start)
		hashiThroughput := float64(size*iterations*2) / hashiTime.Seconds() / 1024 / 1024
		
		// Calculate speedup
		speedup := float64(hashiTime) / float64(ourTime)
		
		// Results
		fmt.Printf("Our implementation:      %v (%.2f MB/s)\n", ourTime, ourThroughput)
		fmt.Printf("HashiCorp implementation: %v (%.2f MB/s)\n", hashiTime, hashiThroughput)
		fmt.Printf("Speedup: %.1fx faster\n", speedup)
	}
	
	fmt.Println("\n=== Memory Usage Comparison ===")
	
	secret := make([]byte, 4096)
	for i := range secret {
		secret[i] = byte(i % 256)
	}
	
	// Our implementation
	ourShares, _ := shamir.Split(secret, 5, 3)
	ourTotalSize := 0
	for _, share := range ourShares {
		ourTotalSize += len(share)
	}
	
	// HashiCorp implementation  
	hashiShares, _ := hashiShamir.Split(secret, 5, 3)
	hashiTotalSize := 0
	for _, share := range hashiShares {
		hashiTotalSize += len(share)
	}
	
	fmt.Printf("Original secret size: %d bytes\n", len(secret))
	fmt.Printf("Our shares total: %d bytes (%d bytes per share)\n", ourTotalSize, len(ourShares[0]))
	fmt.Printf("HashiCorp shares total: %d bytes (%d bytes per share)\n", hashiTotalSize, len(hashiShares[0]))
	fmt.Printf("Overhead comparison: Both have %d byte overhead per share\n", shamir.ShareOverhead)
}