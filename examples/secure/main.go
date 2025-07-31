package main

import (
	"fmt"
	"log"

	"github.com/rizkytaufiq/go-shamir"
)

func main() {
	fmt.Println("=== Secure Shamir Secret Sharing Example ===")
	
	secret := []byte("highly-confidential-data")
	fmt.Printf("Original secret: %s\n", secret)
	
	// Split with integrity checks
	fmt.Println("\nSplitting with integrity checks...")
	shares, err := shamir.SplitWithIntegrity(secret, 7, 4)
	if err != nil {
		log.Fatalf("Failed to split with integrity: %v", err)
	}
	
	fmt.Printf("Generated %d shares with CRC32 checksums\n", len(shares))
	fmt.Printf("Share size: %d bytes (original: %d + overhead: %d + checksum: 4)\n", 
		len(shares[0]), len(secret), shamir.ShareOverhead)
	
	// Reconstruct with integrity validation
	fmt.Println("\nReconstructing with integrity validation...")
	reconstructed, err := shamir.CombineWithIntegrity(shares[:4])
	if err != nil {
		log.Fatalf("Failed to reconstruct with integrity: %v", err)
	}
	
	fmt.Printf("Reconstructed secret: %s\n", reconstructed)
	fmt.Println("✅ Integrity checks passed!")
	
	// Demonstrate corruption detection
	fmt.Println("\nTesting corruption detection...")
	corruptedShares := make([][]byte, len(shares))
	for i, share := range shares {
		corruptedShares[i] = make([]byte, len(share))
		copy(corruptedShares[i], share)
	}
	
	// Corrupt one byte in the first share
	corruptedShares[0][5] ^= 0xFF
	
	_, err = shamir.CombineWithIntegrity(corruptedShares[:4])
	if err != nil {
		fmt.Printf("✅ Corruption detected: %v\n", err)
	} else {
		fmt.Println("❌ Corruption not detected!")
	}
	
	// Demonstrate secure operations with threshold enforcement
	fmt.Println("\nUsing secure operations with threshold enforcement...")
	secureShares, err := shamir.SplitSecure(secret, 5, 3, true)
	if err != nil {
		log.Fatalf("Failed secure split: %v", err)
	}
	
	// Try with insufficient shares
	_, err = shamir.CombineSecure(secureShares[:2], 3)
	if err != nil {
		fmt.Printf("✅ Threshold enforcement working: %v\n", err)
	}
	
	// Reconstruct with correct threshold
	secureReconstructed, err := shamir.CombineSecure(secureShares[:3], 3)
	if err != nil {
		log.Fatalf("Failed secure combine: %v", err)
	}
	
	fmt.Printf("Secure reconstruction successful: %s\n", secureReconstructed)
	fmt.Println("✅ All security features working correctly!")
}