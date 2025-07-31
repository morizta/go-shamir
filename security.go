package shamir

import (
	"hash/crc32"
	"runtime"
	"unsafe"
)

func secureZeroBytes(b []byte) {
	if len(b) == 0 {
		return
	}
	
	for i := range b {
		b[i] = 0
	}
	
	runtime.KeepAlive(b)
}

func secureOverwriteSlice(slice []byte) {
	if len(slice) == 0 {
		return
	}
	
	n := len(slice)
	ptr := unsafe.Pointer(&slice[0])
	
	for i := 0; i < n; i += 8 {
		end := i + 8
		if end > n {
			end = n
		}
		
		if end-i >= 8 {
			*(*uint64)(unsafe.Pointer(uintptr(ptr) + uintptr(i))) = 0
		} else {
			for j := i; j < end; j++ {
				slice[j] = 0
			}
		}
	}
	
	runtime.KeepAlive(slice)
}

func calculateCRC32(data []byte) uint32 {
	return crc32.ChecksumIEEE(data)
}

func addIntegrityCheck(share []byte) []byte {
	if len(share) < 2 {
		return share
	}
	
	payload := share[1:]
	checksum := calculateCRC32(payload)
	
	result := make([]byte, len(share)+4)
	result[0] = share[0] 
	copy(result[1:len(share)], share[1:])
	
	result[len(share)] = byte(checksum)
	result[len(share)+1] = byte(checksum >> 8)
	result[len(share)+2] = byte(checksum >> 16)
	result[len(share)+3] = byte(checksum >> 24)
	
	return result
}

func validateIntegrityCheck(share []byte) ([]byte, error) {
	if len(share) < 6 {
		return share, nil
	}
	
	payloadLen := len(share) - 4
	payload := share[1:payloadLen]
	
	expectedChecksum := calculateCRC32(payload)
	actualChecksum := uint32(share[payloadLen]) |
		uint32(share[payloadLen+1])<<8 |
		uint32(share[payloadLen+2])<<16 |
		uint32(share[payloadLen+3])<<24
	
	if expectedChecksum != actualChecksum {
		return nil, ErrIntegrityCheckFailed
	}
	
	result := make([]byte, payloadLen)
	result[0] = share[0]
	copy(result[1:], payload)
	
	return result, nil
}