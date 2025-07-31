package main

import (
	"fmt"
	"log"

	"github.com/rizkytaufiq/go-shamir"
)

func main() {
	fmt.Println("=== Basic Shamir Secret Sharing Example ===")
	
	secret := []byte("my-secret-password-123")
	fmt.Printf("Original secret: %s\n", secret)
	
	// Split secret into 5 shares, requiring 3 to reconstruct
	fmt.Println("\nSplitting secret into 5 shares (threshold: 3)...")
	shares, err := shamir.Split(secret, 5, 3)
	if err != nil {
		log.Fatalf("Failed to split secret: %v", err)
	}
	
	fmt.Printf("Generated %d shares:\n", len(shares))
	for i, share := range shares {
		fmt.Printf("  Share %d: %x\n", i+1, share)
	}
	
	// Reconstruct using exactly the threshold number of shares
	fmt.Println("\nReconstructing secret using shares 1, 3, and 5...")
	selectedShares := [][]byte{shares[0], shares[2], shares[4]}
	
	reconstructed, err := shamir.Combine(selectedShares)
	if err != nil {
		log.Fatalf("Failed to reconstruct secret: %v", err)
	}
	
	fmt.Printf("Reconstructed secret: %s\n", reconstructed)
	
	// Verify reconstruction
	if string(reconstructed) == string(secret) {
		fmt.Println("✅ Success! Secret reconstructed correctly.")
	} else {
		fmt.Println("❌ Error! Reconstruction failed.")
	}
	
	// Demonstrate that fewer than threshold shares cannot reconstruct
	fmt.Println("\nTrying to reconstruct with only 2 shares (below threshold)...")
	_, err = shamir.Combine(shares[:2])
	if err != nil {
		fmt.Printf("Expected error: %v\n", err)
	}
}