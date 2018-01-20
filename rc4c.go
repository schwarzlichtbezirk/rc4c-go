// Copyright 2018 schwarzlichtbezirk. All rights reserved.
// See https://github.com/schwarzlichtbezirk/rc4c-go
// Package rc4c implements RC4C encryption, it's RC4 extension with two S-boxes
// on key and IV, and with 3 scrambling phases.
package rc4c

import "strconv"

// A Cipher is an instance of RC4C using a particular key.
type Cipher struct {
	s1, s2    [256]uint8
	i, j1, j2 uint8
}

type KeySizeError int

func (k KeySizeError) Error() string {
	return "crypto/rc4c: invalid key size " + strconv.Itoa(int(k))
}

type IvSizeError int

func (k IvSizeError) Error() string {
	return "crypto/rc4c: invalid iv size " + strconv.Itoa(int(k))
}

// NewCipher creates and returns a new Cipher. The key argument should be the
// RC4C key and RC4C iv, at least 1 byte and at most 256 bytes any of them.
func NewCipher(key []byte, iv []byte) (*Cipher, error) {
	var l1, l2 = len(key), len(iv)
	if l1 < 1 || l1 > 256 {
		return nil, KeySizeError(l1)
	}
	if l2 < 1 || l2 > 256 {
		return nil, IvSizeError(l2)
	}

	var c Cipher
	var s1, s2 = &c.s1, &c.s2
	for i := 0; i < 256; i++ {
		s1[i], s2[i] = uint8(i), uint8(i)
	}

	var j uint8
	j = 0
	for i := 0; i < 256; i++ {
		j += s1[i] + key[i%l1]
		s1[i], s1[j] = s1[j], s1[i]
	}

	j = 0
	for i := 0; i < 256; i++ {
		j += s2[i] + iv[i%l2]
		s2[i], s2[j] = s2[j], s2[i]
	}

	return &c, nil
}

// Reset zeros the key data so that it will no longer appear in the
// process's memory.
func (c *Cipher) Reset() {
	for i := 0; i < 256; i++ {
		c.s1[i], c.s2[i] = 0, 0
	}
	c.i, c.j1, c.j2 = 255, 0, 0
}

// XORKeyStream sets dst to the result of XORing src with the key stream.
// Dst and src may be the same slice but otherwise should not overlap.
func (c *Cipher) XORKeyStream(dst, src []byte) {
	var s1, s2 = &c.s1, &c.s2
	var i, j1, j2 = c.i, c.j1, c.j2
	for k, v := range src {
		i++
		j1 += s1[i]
		j2 += s2[i]

		s1[i], s1[j1] = s1[j1], s1[i]
		s2[i], s2[j2] = s2[j2], s2[i]

		dst[k] = v ^ s1[s1[i<<5^i>>3]+s2[i<<3^i>>5]+s1[j2]+s2[j1]]
	}
	c.i, c.j1, c.j2 = i, j1, j2
}

// The End.
