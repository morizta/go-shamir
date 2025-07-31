package shamir

import (
	"fmt"
	"testing"
	
	hashiShamir "github.com/hashicorp/vault/shamir"
)

var benchmarkSizes = []int{32, 256, 1024, 4096, 16384, 65536}

func BenchmarkSplitOurs(b *testing.B) {
	for _, size := range benchmarkSizes {
		b.Run(fmt.Sprintf("size_%d", size), func(b *testing.B) {
			secret := make([]byte, size)
			for i := range secret {
				secret[i] = byte(i % 256)
			}
			
			b.ResetTimer()
			b.SetBytes(int64(size))
			
			for i := 0; i < b.N; i++ {
				_, err := Split(secret, 5, 3)
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkSplitHashiCorp(b *testing.B) {
	for _, size := range benchmarkSizes {
		b.Run(fmt.Sprintf("size_%d", size), func(b *testing.B) {
			secret := make([]byte, size)
			for i := range secret {
				secret[i] = byte(i % 256)
			}
			
			b.ResetTimer()
			b.SetBytes(int64(size))
			
			for i := 0; i < b.N; i++ {
				_, err := hashiShamir.Split(secret, 5, 3)
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkCombineOurs(b *testing.B) {
	for _, size := range benchmarkSizes {
		b.Run(fmt.Sprintf("size_%d", size), func(b *testing.B) {
			secret := make([]byte, size)
			for i := range secret {
				secret[i] = byte(i % 256)
			}
			
			shares, err := Split(secret, 5, 3)
			if err != nil {
				b.Fatal(err)
			}
			
			b.ResetTimer()
			b.SetBytes(int64(size))
			
			for i := 0; i < b.N; i++ {
				_, err := Combine(shares[:3])
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkCombineHashiCorp(b *testing.B) {
	for _, size := range benchmarkSizes {
		b.Run(fmt.Sprintf("size_%d", size), func(b *testing.B) {
			secret := make([]byte, size)
			for i := range secret {
				secret[i] = byte(i % 256)
			}
			
			shares, err := hashiShamir.Split(secret, 5, 3)
			if err != nil {
				b.Fatal(err)
			}
			
			b.ResetTimer()
			b.SetBytes(int64(size))
			
			for i := 0; i < b.N; i++ {
				_, err := hashiShamir.Combine(shares[:3])
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkGFOperations(b *testing.B) {
	a := byte(123)
	buf := make([]byte, 1024)
	for i := range buf {
		buf[i] = byte(i % 256)
	}
	
	b.Run("gfMult", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_ = gfMult(a, byte(i%256))
		}
	})
	
	b.Run("gfMultSlice", func(b *testing.B) {
		dst := make([]byte, 1024)
		b.ResetTimer()
		b.SetBytes(1024)
		
		for i := 0; i < b.N; i++ {
			gfMultSlice(dst, buf, a)
		}
	})
	
	b.Run("gfAddSlice", func(b *testing.B) {
		dst := make([]byte, 1024)
		buf2 := make([]byte, 1024)
		copy(buf2, buf)
		
		b.ResetTimer()
		b.SetBytes(1024)
		
		for i := 0; i < b.N; i++ {
			gfAddSlice(dst, buf, buf2)
		}
	})
}