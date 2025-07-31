package shamir

import "unsafe"

var (
	expTable [256]byte
	logTable [256]byte
)

func init() {
	buildTables()
}

func buildTables() {
	x := 1
	for i := 0; i < 255; i++ {
		expTable[i] = byte(x)
		logTable[x] = byte(i)
		x = (x << 1) ^ ((x >> 7) * 0x11d)
	}
	expTable[255] = expTable[0]
	logTable[0] = 255
}

// gfAdd performs Galois Field addition (XOR) - kept for mathematical completeness
func gfAdd(a, b byte) byte {
	return a ^ b
}

func gfMult(a, b byte) byte {
	if a == 0 || b == 0 {
		return 0
	}
	return expTable[(int(logTable[a])+int(logTable[b]))%255]
}

// gfDiv performs Galois Field division - kept for mathematical completeness
func gfDiv(a, b byte) byte {
	if a == 0 {
		return 0
	}
	if b == 0 {
		panic("division by zero")
	}
	return expTable[(int(logTable[a])-int(logTable[b])+255)%255]
}

// gfInv computes multiplicative inverse in GF(256) - kept for mathematical completeness
func gfInv(a byte) byte {
	if a == 0 {
		panic("inversion of zero")
	}
	return expTable[255-int(logTable[a])]
}

func gfMultSlice(dst, a []byte, b byte) {
	if b == 0 {
		for i := range dst {
			dst[i] = 0
		}
		return
	}
	if b == 1 {
		copy(dst, a)
		return
	}
	
	logB := logTable[b]
	for i := 0; i < len(a); i += 8 {
		end := i + 8
		if end > len(a) {
			end = len(a)
		}
		
		for j := i; j < end; j++ {
			if a[j] == 0 {
				dst[j] = 0
			} else {
				dst[j] = expTable[(int(logTable[a[j]])+int(logB))%255]
			}
		}
	}
}

func gfAddSlice(dst, a, b []byte) {
	n := len(a)
	if len(b) < n {
		n = len(b)
	}
	
	i := 0
	for i+8 <= n {
		*(*uint64)(unsafe.Pointer(&dst[i])) = 
			*(*uint64)(unsafe.Pointer(&a[i])) ^ 
			*(*uint64)(unsafe.Pointer(&b[i]))
		i += 8
	}
	
	for i < n {
		dst[i] = a[i] ^ b[i]
		i++
	}
}

// gfPolyEval evaluates polynomial at point x - single byte version, kept for reference
func gfPolyEval(coeffs []byte, x byte) byte {
	if len(coeffs) == 0 {
		return 0
	}
	
	result := coeffs[len(coeffs)-1]
	for i := len(coeffs) - 2; i >= 0; i-- {
		result = gfMult(result, x) ^ coeffs[i]
	}
	return result
}

func gfPolyEvalSlice(dst []byte, coeffs [][]byte, x byte) {
	if len(coeffs) == 0 || len(dst) == 0 {
		return
	}
	
	copy(dst, coeffs[len(coeffs)-1])
	
	for i := len(coeffs) - 2; i >= 0; i-- {
		gfMultSlice(dst, dst, x)
		gfAddSlice(dst, dst, coeffs[i])
	}
}