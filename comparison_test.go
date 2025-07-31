package shamir

import (
	"fmt"
	"testing"
	
	hashiShamir "github.com/hashicorp/vault/shamir"
)

func BenchmarkComparison(b *testing.B) {
	sizes := []int{32, 256, 1024, 4096, 16384, 65536}
	
	for _, size := range sizes {
		secret := make([]byte, size)
		for i := range secret {
			secret[i] = byte(i % 256)
		}
		
		b.Run(fmt.Sprintf("Split_%dB", size), func(b *testing.B) {
			b.Run("Ours", func(b *testing.B) {
				b.ResetTimer()
				b.SetBytes(int64(size))
				for i := 0; i < b.N; i++ {
					_, err := Split(secret, 5, 3)
					if err != nil {
						b.Fatal(err)
					}
				}
			})
			
			b.Run("HashiCorp", func(b *testing.B) {
				b.ResetTimer()
				b.SetBytes(int64(size))
				for i := 0; i < b.N; i++ {
					_, err := hashiShamir.Split(secret, 5, 3)
					if err != nil {
						b.Fatal(err)
					}
				}
			})
		})
		
		ourShares, _ := Split(secret, 5, 3)
		hashiShares, _ := hashiShamir.Split(secret, 5, 3)
		
		b.Run(fmt.Sprintf("Combine_%dB", size), func(b *testing.B) {
			b.Run("Ours", func(b *testing.B) {
				b.ResetTimer()
				b.SetBytes(int64(size))
				for i := 0; i < b.N; i++ {
					_, err := Combine(ourShares[:3])
					if err != nil {
						b.Fatal(err)
					}
				}
			})
			
			b.Run("HashiCorp", func(b *testing.B) {
				b.ResetTimer()
				b.SetBytes(int64(size))
				for i := 0; i < b.N; i++ {
					_, err := hashiShamir.Combine(hashiShares[:3])
					if err != nil {
						b.Fatal(err)
					}
				}
			})
		})
	}
}