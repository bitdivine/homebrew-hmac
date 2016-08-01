package main

import "encoding/binary"

// This is an implementation of SHA256 from scratch.
// Reference: http://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf
// Validation:  http://csrc.nist.gov/groups/ST/toolkit/examples.html#aHashing
// Validation:  http://csrc.nist.gov/groups/ST/toolkit/documents/Examples/SHA3-256_Msg0.pdf
// WARNING: This is work in progress.  This hash currently fails the test vectors.

var ih [8]uint32	// The initial value of the hash registers - see page 15.
var k [64]uint32	// The round constants - see page 11.

func init() {
	ih = [8]uint32{	0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19 }
	k = [64]uint32{	0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
			0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
			0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
			0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
			0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
			0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
			0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
			0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2 }
}

// Intermediate functions - see page 10.
func Ch(x uint32, y uint32, z uint32) uint32 {
	return (x & y) ^ (^x & z)
}
func Maj(x uint32, y uint32, z uint32) uint32 {
	return (x & y) ^ (x & z) ^ (y & z)
}
func SHR(n uint, x uint32) uint32 {
	return x >> n
}
func SHL(n uint, x uint32) uint32 {
	return x << n
}
func ROTR(n uint, x uint32) uint32 {
	n = n % 32
	return SHR(n, x) | SHL(32-n, x)
}
func sigma_0_256(x uint32) uint32 {
	return ROTR(2,x) ^ ROTR(13,x) ^ ROTR(22, x)
}
func sigma_1_256(x uint32) uint32 {
	return ROTR(6,x) ^ ROTR(11,x) ^ ROTR(25, x)
}
func mini_sigma_0_256(x uint32) uint32 {
	return ROTR(7,x) ^ ROTR(18,x) ^ SHR(3, x)
}
func mini_sigma_1_256(x uint32) uint32 {
	return ROTR(17,x) ^ ROTR(19,x) ^ SHR(10, x)
}
func bytes2block(b []byte) [16]uint32 {
	var ans [16]uint32
	for i,_ := range ans {
		ans[i] = binary.BigEndian.Uint32(b[i*4:i*4+4])
	}
	return ans
}

func TEST_SHA256 (message []byte) [32]byte {
	var hash [8]uint32
	copy(hash[:], ih[:])
	message_length := len(message)
	// The complete blocks:
	for complete_block_num:=0; complete_block_num < message_length/64; complete_block_num++ {
		block := bytes2block(message[complete_block_num * 64: complete_block_num * 64 + 64])
		hash = SHA256_round(hash, block)
	}
	// Populate the first padded block:
	remaining_length := message_length % 64
	have_length := remaining_length < (64 -1 -16) // Need one terminator and 16 length bytes to fit the padding in one block.
	{
		var byte_block [64]byte
		for byte_num:=0; byte_num < remaining_length; byte_num += 1 {
			byte_block[byte_num] = message[message_length/64 + byte_num]
		}
		byte_block[remaining_length] = 0x80
		block := bytes2block(byte_block[:])
		if have_length { // Note: I THINK the endianness here is OK.
			message_bitlen := message_length * 8
			block[16-4] = uint32((uint64(message_bitlen)>>96) & 0xffffffff)
			block[16-3] = uint32((uint64(message_bitlen)>>64) & 0xffffffff)
			block[16-2] = uint32((uint64(message_bitlen)>>32) & 0xffffffff)
			block[16-1] = uint32((uint64(message_bitlen)    ) & 0xffffffff)
		}
		hash = SHA256_round(hash, block)
	}
	// We may need a second padded block:
	if false == have_length {
		var block [16]uint32
			message_bitlen := message_length * 8
			block[16-4] = uint32((uint64(message_bitlen)>>96) & 0xffffffff)
			block[16-3] = uint32((uint64(message_bitlen)>>64) & 0xffffffff)
			block[16-2] = uint32((uint64(message_bitlen)>>32) & 0xffffffff)
			block[16-1] = uint32((uint64(message_bitlen)    ) & 0xffffffff)
	}
	var ans [32]byte
	for i,u := range hash {
		binary.BigEndian.PutUint32(ans[i*4:i*4+4], u)
	}
	return ans
}

func SHA256_round(hash [8]uint32, message_block [16]uint32) [8]uint32 {
	// The message schedule is on page 22:
	var message_schedule [64]uint32
	for t:=0; t<16; t++ {
		message_schedule[t] = message_block[t]
	}
	for t:=16; t<64; t++ {
		message_schedule[t] =	mini_sigma_1_256(message_schedule[t-2]) + message_schedule[t-7] +
					mini_sigma_0_256(message_schedule[t-15]) + message_schedule[t-16]
	}
	// The hash initialisation is on page 22:
	a,b,c,d,e,f,g,h := hash[0], hash[1], hash[2], hash[3], hash[4], hash[5], hash[6], hash[7]
	// The rounds are on page 23:
	for t:=0; t<64; t+=1 {
		t1 := h + sigma_1_256(e) + Ch(e,f,g) + k[t] + message_schedule[t]
		t2 := sigma_0_256(a) + Maj(a,b,c)
		h = g
		g = f
		f = e
		e = d+t1
		d = c
		c = b
		b = a
		a = t1 + t2
	}
	return [8]uint32{ hash[0] + a, hash[1] + b, hash[2] + c, hash[3] + d,
			  hash[4] + e, hash[5] + f, hash[6] + g, hash[7] + h}
}
