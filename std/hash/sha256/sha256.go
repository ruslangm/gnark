package sha256

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/permutation/keccakf"
)

type Sha256 struct {
	api    frontend.API
	uapi64 *keccakf.Uint64api
	uapi32 *keccakf.Uint32api
	uapi8  *keccakf.Uint8api
}

func newSha256(api frontend.API) Sha256 {
	return Sha256{
		api:    api,
		uapi8:  keccakf.NewUint8API(api),
		uapi32: keccakf.NewUint32API(api),
		uapi64: keccakf.NewUint64API(api),
	}
}

func Sha256Api(api frontend.API, data ...frontend.Variable) frontend.Variable {
	sha := newSha256(api)
	uapi8 := sha.uapi8
	uapi32 := sha.uapi32
	gnark := sha.api

	in := make([]keccakf.Xuint8, len(data))
	for i := range data {
		in[i] = uapi8.AsUint8(data[i])
	}

	h0 := frontend.Variable(0x6a09e667)
	h1 := frontend.Variable(0xbb67ae85)
	h2 := frontend.Variable(0x3c6ef372)
	h3 := frontend.Variable(0xa54ff53a)
	h4 := frontend.Variable(0x510e527f)
	h5 := frontend.Variable(0x9b05688c)
	h6 := frontend.Variable(0x1f83d9ab)
	h7 := frontend.Variable(0x5be0cd19)

	k := [64]frontend.Variable{
		frontend.Variable(0x428a2f98), frontend.Variable(0x71374491), frontend.Variable(0xb5c0fbcf), frontend.Variable(0xe9b5dba5), frontend.Variable(0x3956c25b), frontend.Variable(0x59f111f1), frontend.Variable(0x923f82a4), frontend.Variable(0xab1c5ed5),
		frontend.Variable(0xd807aa98), frontend.Variable(0x12835b01), frontend.Variable(0x243185be), frontend.Variable(0x550c7dc3), frontend.Variable(0x72be5d74), frontend.Variable(0x80deb1fe), frontend.Variable(0x9bdc06a7), frontend.Variable(0xc19bf174),
		frontend.Variable(0xe49b69c1), frontend.Variable(0xefbe4786), frontend.Variable(0x0fc19dc6), frontend.Variable(0x240ca1cc), frontend.Variable(0x2de92c6f), frontend.Variable(0x4a7484aa), frontend.Variable(0x5cb0a9dc), frontend.Variable(0x76f988da),
		frontend.Variable(0x983e5152), frontend.Variable(0xa831c66d), frontend.Variable(0xb00327c8), frontend.Variable(0xbf597fc7), frontend.Variable(0xc6e00bf3), frontend.Variable(0xd5a79147), frontend.Variable(0x06ca6351), frontend.Variable(0x14292967),
		frontend.Variable(0x27b70a85), frontend.Variable(0x2e1b2138), frontend.Variable(0x4d2c6dfc), frontend.Variable(0x53380d13), frontend.Variable(0x650a7354), frontend.Variable(0x766a0abb), frontend.Variable(0x81c2c92e), frontend.Variable(0x92722c85),
		frontend.Variable(0xa2bfe8a1), frontend.Variable(0xa81a664b), frontend.Variable(0xc24b8b70), frontend.Variable(0xc76c51a3), frontend.Variable(0xd192e819), frontend.Variable(0xd6990624), frontend.Variable(0xf40e3585), frontend.Variable(0x106aa070),
		frontend.Variable(0x19a4c116), frontend.Variable(0x1e376c08), frontend.Variable(0x2748774c), frontend.Variable(0x34b0bcb5), frontend.Variable(0x391c0cb3), frontend.Variable(0x4ed8aa4a), frontend.Variable(0x5b9cca4f), frontend.Variable(0x682e6ff3),
		frontend.Variable(0x748f82ee), frontend.Variable(0x78a5636f), frontend.Variable(0x84c87814), frontend.Variable(0x8cc70208), frontend.Variable(0x90befffa), frontend.Variable(0xa4506ceb), frontend.Variable(0xbef9a3f7), frontend.Variable(0xc67178f2)}

	schedule := padding(data, sha)

	for _, chunk := range schedule {
		var w []keccakf.Xuint32
		for i := 0; i < 16; i++ {
			chunk32 := []keccakf.Xuint8{uapi8.AsUint8(chunk[i*4]), uapi8.AsUint8(chunk[i*4+1]), uapi8.AsUint8(chunk[i*4+2]), uapi8.AsUint8(chunk[i*4+3])}
			w = append(w, uapi8.DecodeToXuint32BigEndian(chunk32))
		}
		w = append(w, make([]keccakf.Xuint32, 48)...)
		for i := 16; i < 64; i++ {
			w[i] = keccakf.ConstUint32(0)
		}

		for i := 16; i < 64; i++ {
			// s0 := (w[i-15] rightrotate 7) xor (w[i-15] rightrotate 18) xor (w[i-15] rightshift 3)
			s0 := uapi32.Xor(sha.rightRotate(w[i-15], 7), sha.rightRotate(w[i-15], 18), sha.rightShift(w[i-15], 3))

			// s1 := (w[i-2] rightrotate 17) xor (w[i-2] rightrotate 19) xor (w[i-2] rightshift 10)
			s1 := uapi32.Xor(sha.rightRotate(w[i-2], 17), sha.rightRotate(w[i-2], 19), sha.rightShift(w[i-2], 10))

			sum1 := gnark.Add(uapi32.FromUint32(w[i-16]), uapi32.FromUint32(s0))
			sum2 := gnark.Add(uapi32.FromUint32(w[i-7]), uapi32.FromUint32(s1))

			// w[i] := w[i-16] + s0 + w[i-7] + s1
			w[i] = uapi32.AsUint32(sha.trimBits(gnark.Add(sum1, sum2), 34))
		}

		a := uapi32.AsUint32(h0)
		b := uapi32.AsUint32(h1)
		c := uapi32.AsUint32(h2)
		d := uapi32.AsUint32(h3)
		e := uapi32.AsUint32(h4)
		f := uapi32.AsUint32(h5)
		g := uapi32.AsUint32(h6)
		h := uapi32.AsUint32(h7)

		for i := 0; i < 64; i++ {
			// S1 := (e rightrotate 6) xor (e rightrotate 11) xor (e rightrotate 25)
			S1 := uapi32.Xor(sha.rightRotate(e, 6), sha.rightRotate(e, 11), sha.rightRotate(e, 25))

			// ch := (e and f) xor ((not e) and g)
			ch := uapi32.Xor(uapi32.And(e, f), uapi32.And(uapi32.Not(e), g))

			sum1 := gnark.Add(uapi32.FromUint32(h), uapi32.FromUint32(S1))
			sum2 := gnark.Add(uapi32.FromUint32(ch), k[i])
			sum3 := gnark.Add(sum2, uapi32.FromUint32(w[i]))

			// temp1 := h + S1 + ch + k[i] + w[i]
			temp1 := gnark.Add(sum1, sum3)

			// S0 := (a rightrotate 2) xor (a rightrotate 13) xor (a rightrotate 22)
			S0 := uapi32.Xor(sha.rightRotate(a, 2), sha.rightRotate(a, 13), sha.rightRotate(a, 22))

			// https://github.com/akosba/jsnark/blob/master/JsnarkCircuitBuilder/src/examples/gadgets/hash/SHA256Gadget.java
			minusTwo := [32]frontend.Variable{0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1} // -2 in little endian, of size 32
			// tmp4Bits := sha.api.ToBinary(0, 32)
			tmp4Bits := make([]frontend.Variable, 32)
			var x, y, z []frontend.Variable
			if i%2 == 1 {
				x = c[:]
				y = b[:]
				z = a[:]
			} else {
				x = a[:]
				y = b[:]
				z = c[:]
			}

			for j := 0; j < 32; j++ {
				t4t1 := gnark.And(x[j], y[j])
				t4t2 := gnark.Or(gnark.Or(x[j], y[j]), gnark.And(t4t1, minusTwo[j]))
				tmp4Bits[j] = gnark.Or(t4t1, gnark.And(z[j], t4t2))
			}
			tmp4 := gnark.FromBinary(tmp4Bits...)

			// t2 computation
			temp2 := gnark.Add(uapi32.FromUint32(S0), tmp4)

			/*
			   h := g
			   g := f
			   f := e
			   e := d + temp1
			   d := c
			   c := b
			   b := a
			   a := temp1 + temp2
			*/
			h = g
			g = f
			f = e
			e = uapi32.AsUint32(sha.trimBits(gnark.Add(uapi32.FromUint32(d), temp1), 35))
			d = c
			c = b
			b = a
			a = uapi32.AsUint32(sha.trimBits(gnark.Add(temp1, temp2), 35))
		}

		/*
		   Add the compressed chunk to the current hash value:
		   h0 := h0 + a
		   h1 := h1 + b
		   h2 := h2 + c
		   h3 := h3 + d
		   h4 := h4 + e
		   h5 := h5 + f
		   h6 := h6 + g
		   h7 := h7 + h
		*/
		h0 = sha.trimBits(gnark.Add(h0, uapi32.FromUint32(a)), 33)
		h1 = sha.trimBits(gnark.Add(h1, uapi32.FromUint32(b)), 33)
		h2 = sha.trimBits(gnark.Add(h2, uapi32.FromUint32(c)), 33)
		h3 = sha.trimBits(gnark.Add(h3, uapi32.FromUint32(d)), 33)
		h4 = sha.trimBits(gnark.Add(h4, uapi32.FromUint32(e)), 33)
		h5 = sha.trimBits(gnark.Add(h5, uapi32.FromUint32(f)), 33)
		h6 = sha.trimBits(gnark.Add(h6, uapi32.FromUint32(g)), 33)
		h7 = sha.trimBits(gnark.Add(h7, uapi32.FromUint32(h)), 33)
	}

	hashBytes := [][]keccakf.Xuint8{
		sha.toBytes(uapi32.AsUint32(h0)),
		sha.toBytes(uapi32.AsUint32(h1)),
		sha.toBytes(uapi32.AsUint32(h2)),
		sha.toBytes(uapi32.AsUint32(h3)),
		sha.toBytes(uapi32.AsUint32(h4)),
		sha.toBytes(uapi32.AsUint32(h5)),
		sha.toBytes(uapi32.AsUint32(h6)),
		sha.toBytes(uapi32.AsUint32(h7)),
	}
	var res []keccakf.Xuint8
	for i := 0; i < 8; i++ {
		res = append(res, hashBytes[i]...)
	}
	res = res[0:32]

	var sha256Bits []frontend.Variable
	for i := len(res) - 1; i >= 0; i-- {
		sha256Bits = append(sha256Bits, res[i][:]...)
	}

	return api.FromBinary(sha256Bits[:]...)
}

func padding(in []frontend.Variable, sha Sha256) [][]frontend.Variable {
	padded := append(in, frontend.Variable(0x80))
	if len(padded)%64 < 56 {
		suffix := make([]frontend.Variable, 56-(len(padded)%64))
		for i := 0; i < len(suffix); i++ {
			suffix[i] = frontend.Variable(0)
		}
		padded = append(padded, suffix...)
	} else {
		suffix := make([]frontend.Variable, 64+56-(len(padded)%64))
		for i := 0; i < len(suffix); i++ {
			suffix[i] = frontend.Variable(0)
		}
		padded = append(padded, suffix...)
	}
	msgLen := len(in) * 8

	bits := sha.api.ToBinary(msgLen, 64) // 64 bit = 8 byte
	for i := 7; i >= 0; i-- {
		start := i * 8
		padded = append(padded, sha.api.FromBinary(bits[start:start+8]...))
	}

	var schedule [][]frontend.Variable
	for i := 0; i < len(padded)/64; i++ {
		schedule = append(schedule, padded[i*64:i*64+64])
	}
	return schedule
}

func (h *Sha256) toBytes(x keccakf.Xuint32) []keccakf.Xuint8 {
	return h.uapi32.EncodeToXuint8BigEndian(x)
}

func (h *Sha256) rightRotate(n keccakf.Xuint32, shift int) keccakf.Xuint32 {
	return h.uapi32.Rrot(n, shift)
}

func (h *Sha256) rightShift(n keccakf.Xuint32, shift int) keccakf.Xuint32 {
	return h.uapi32.Rshift(n, shift)
}

// https://github.com/akosba/jsnark/blob/master/JsnarkCircuitBuilder/src/examples/gadgets/hash/SHA256Gadget.java
func (h *Sha256) trimBits(a frontend.Variable, size int) frontend.Variable {
	requiredSize := 32
	aBits := h.api.ToBinary(a, size)
	x := make([]frontend.Variable, requiredSize)

	for i := requiredSize; i < size; i++ {
		aBits[i] = 0
	}
	for i := 0; i < requiredSize; i++ {
		x[i] = aBits[i]
	}

	return h.api.FromBinary(x...)
}
