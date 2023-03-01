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

	in := make([]keccakf.Xuint8, len(data))
	for i := range data {
		in[i] = sha.uapi8.AsUint8(data[i])
	}

	h0 := keccakf.ConstUint32(0x6a09e667)
	h1 := keccakf.ConstUint32(0xbb67ae85)
	h2 := keccakf.ConstUint32(0x3c6ef372)
	h3 := keccakf.ConstUint32(0xa54ff53a)
	h4 := keccakf.ConstUint32(0x510e527f)
	h5 := keccakf.ConstUint32(0x9b05688c)
	h6 := keccakf.ConstUint32(0x1f83d9ab)
	h7 := keccakf.ConstUint32(0x5be0cd19)

	k := [64]keccakf.Xuint32{
		keccakf.ConstUint32(0x428a2f98), keccakf.ConstUint32(0x71374491), keccakf.ConstUint32(0xb5c0fbcf), keccakf.ConstUint32(0xe9b5dba5), keccakf.ConstUint32(0x3956c25b), keccakf.ConstUint32(0x59f111f1), keccakf.ConstUint32(0x923f82a4), keccakf.ConstUint32(0xab1c5ed5),
		keccakf.ConstUint32(0xd807aa98), keccakf.ConstUint32(0x12835b01), keccakf.ConstUint32(0x243185be), keccakf.ConstUint32(0x550c7dc3), keccakf.ConstUint32(0x72be5d74), keccakf.ConstUint32(0x80deb1fe), keccakf.ConstUint32(0x9bdc06a7), keccakf.ConstUint32(0xc19bf174),
		keccakf.ConstUint32(0xe49b69c1), keccakf.ConstUint32(0xefbe4786), keccakf.ConstUint32(0x0fc19dc6), keccakf.ConstUint32(0x240ca1cc), keccakf.ConstUint32(0x2de92c6f), keccakf.ConstUint32(0x4a7484aa), keccakf.ConstUint32(0x5cb0a9dc), keccakf.ConstUint32(0x76f988da),
		keccakf.ConstUint32(0x983e5152), keccakf.ConstUint32(0xa831c66d), keccakf.ConstUint32(0xb00327c8), keccakf.ConstUint32(0xbf597fc7), keccakf.ConstUint32(0xc6e00bf3), keccakf.ConstUint32(0xd5a79147), keccakf.ConstUint32(0x06ca6351), keccakf.ConstUint32(0x14292967),
		keccakf.ConstUint32(0x27b70a85), keccakf.ConstUint32(0x2e1b2138), keccakf.ConstUint32(0x4d2c6dfc), keccakf.ConstUint32(0x53380d13), keccakf.ConstUint32(0x650a7354), keccakf.ConstUint32(0x766a0abb), keccakf.ConstUint32(0x81c2c92e), keccakf.ConstUint32(0x92722c85),
		keccakf.ConstUint32(0xa2bfe8a1), keccakf.ConstUint32(0xa81a664b), keccakf.ConstUint32(0xc24b8b70), keccakf.ConstUint32(0xc76c51a3), keccakf.ConstUint32(0xd192e819), keccakf.ConstUint32(0xd6990624), keccakf.ConstUint32(0xf40e3585), keccakf.ConstUint32(0x106aa070),
		keccakf.ConstUint32(0x19a4c116), keccakf.ConstUint32(0x1e376c08), keccakf.ConstUint32(0x2748774c), keccakf.ConstUint32(0x34b0bcb5), keccakf.ConstUint32(0x391c0cb3), keccakf.ConstUint32(0x4ed8aa4a), keccakf.ConstUint32(0x5b9cca4f), keccakf.ConstUint32(0x682e6ff3),
		keccakf.ConstUint32(0x748f82ee), keccakf.ConstUint32(0x78a5636f), keccakf.ConstUint32(0x84c87814), keccakf.ConstUint32(0x8cc70208), keccakf.ConstUint32(0x90befffa), keccakf.ConstUint32(0xa4506ceb), keccakf.ConstUint32(0xbef9a3f7), keccakf.ConstUint32(0xc67178f2)}

	padded := append(in, keccakf.ConstUint8(0x80))
	if len(padded)%64 < 56 {
		suffix := make([]keccakf.Xuint8, 56-(len(padded)%64))
		for i := 0; i < len(suffix); i++ {
			suffix[i] = keccakf.ConstUint8(0)
		}
		padded = append(padded, suffix...)
	} else {
		suffix := make([]keccakf.Xuint8, 64+56-(len(padded)%64))
		for i := 0; i < len(suffix); i++ {
			suffix[i] = keccakf.ConstUint8(0)
		}
		padded = append(padded, suffix...)
	}
	msgLen := len(in) * 8
	var bs []keccakf.Xuint8
	bs = sha.uapi8.EncodeToXuint8(bs, keccakf.ConstUint64(uint64(msgLen)))

	//TODO: move to uapi8
	for i := 7; i >= 0; i-- {
		padded = append(padded, bs[i])
	}

	var schedule [][]keccakf.Xuint8
	for i := 0; i < len(padded)/64; i++ {
		schedule = append(schedule, padded[i*64:i*64+63])
	}
	for _, chunk := range schedule {
		var w []keccakf.Xuint32
		for i := 0; i < 16; i++ {
			w = append(w, sha.uapi8.DecodeToXuint32BigEndian(chunk[i*4:i*4+4]))
		}
		w = append(w, make([]keccakf.Xuint32, 48)...)
		for i := 16; i < 64; i++ {
			w[i] = keccakf.ConstUint32(0)
		}

		for i := 16; i < 64; i++ {
			// s0 := (w[i-15] rightrotate 7) xor (w[i-15] rightrotate 18) xor (w[i-15] rightshift 3)
			s0 := sha.uapi32.Xor(sha.rightRotate(w[i-15], 7), sha.rightRotate(w[i-15], 18), sha.rightShift(w[i-15], 3))

			// s1 := (w[i-2] rightrotate 17) xor (w[i-2] rightrotate 19) xor (w[i-2] rightshift 10)
			s1 := sha.uapi32.Xor(sha.rightRotate(w[i-2], 17), sha.rightRotate(w[i-2], 19), sha.rightShift(w[i-2], 10))

			sum1 := sha.api.Add(sha.uapi32.FromUint32(w[i-16]), sha.uapi32.FromUint32(s0))
			sum2 := sha.api.Add(sha.uapi32.FromUint32(w[i-7]), sha.uapi32.FromUint32(s1))

			// w[i] := w[i-16] + s0 + w[i-7] + s1
			w[i] = sha.uapi32.AsUint32(trimBits(sha.api, sha.api.Add(sum1, sum2), 34))
		}

		a := h0
		b := h1
		c := h2
		d := h3
		e := h4
		f := h5
		g := h6
		h := h7

		for i := 0; i < 64; i++ {
			// S1 := (e rightrotate 6) xor (e rightrotate 11) xor (e rightrotate 25)
			S1 := sha.uapi32.Xor(sha.rightRotate(e, 6), sha.rightRotate(e, 11), sha.rightRotate(e, 25))

			// ch := (e and f) xor ((not e) and g)
			ch := sha.uapi32.Xor(sha.uapi32.And(e, f), sha.uapi32.And(sha.uapi32.Not(e), g))

			sum1 := sha.api.Add(sha.uapi32.FromUint32(h), sha.uapi32.FromUint32(S1))
			sum2 := sha.api.Add(sha.uapi32.FromUint32(ch), sha.uapi32.FromUint32(k[i]))
			sum3 := sha.api.Add(sum2, sha.uapi32.FromUint32(w[i]))

			// temp1 := h + S1 + ch + k[i] + w[i]
			temp1 := sha.api.Add(sum1, sum3)

			// S0 := (a rightrotate 2) xor (a rightrotate 13) xor (a rightrotate 22)
			S0 := sha.uapi32.Xor(sha.rightRotate(a, 2), sha.rightRotate(a, 13), sha.rightRotate(a, 22))

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

			// working with less complexity compared to uncommented tmp4 calculation below works
			for j := 0; j < 32; j++ {
				t4t1 := sha.api.And(x[j], y[j])
				t4t2 := sha.api.Or(sha.api.Or(x[j], y[j]), sha.api.And(t4t1, minusTwo[j]))
				tmp4Bits[j] = sha.api.Or(t4t1, sha.api.And(z[j], t4t2))
			}
			tmp4 := sha.api.FromBinary(tmp4Bits...)

			// t2 computation
			temp2 := sha.api.Add(sha.uapi32.FromUint32(S0), tmp4)

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
			e = sha.uapi32.AsUint32(trimBits(sha.api, sha.api.Add(sha.uapi32.FromUint32(d), temp1), 35))
			d = c
			c = b
			b = a
			a = sha.uapi32.AsUint32(trimBits(sha.api, sha.api.Add(temp1, temp2), 35))
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
		h0 = sha.uapi32.AsUint32(trimBits(sha.api, sha.api.Add(sha.uapi32.FromUint32(h0), sha.uapi32.FromUint32(a)), 33))
		h1 = sha.uapi32.AsUint32(trimBits(sha.api, sha.api.Add(sha.uapi32.FromUint32(h1), sha.uapi32.FromUint32(b)), 33))
		h2 = sha.uapi32.AsUint32(trimBits(sha.api, sha.api.Add(sha.uapi32.FromUint32(h2), sha.uapi32.FromUint32(c)), 33))
		h3 = sha.uapi32.AsUint32(trimBits(sha.api, sha.api.Add(sha.uapi32.FromUint32(h3), sha.uapi32.FromUint32(d)), 33))
		h4 = sha.uapi32.AsUint32(trimBits(sha.api, sha.api.Add(sha.uapi32.FromUint32(h4), sha.uapi32.FromUint32(e)), 33))
		h5 = sha.uapi32.AsUint32(trimBits(sha.api, sha.api.Add(sha.uapi32.FromUint32(h5), sha.uapi32.FromUint32(f)), 33))
		h6 = sha.uapi32.AsUint32(trimBits(sha.api, sha.api.Add(sha.uapi32.FromUint32(h6), sha.uapi32.FromUint32(g)), 33))
		h7 = sha.uapi32.AsUint32(trimBits(sha.api, sha.api.Add(sha.uapi32.FromUint32(h7), sha.uapi32.FromUint32(h)), 33))
	}

	hashBytes := [][]keccakf.Xuint8{sha.iToB(h0), sha.iToB(h1), sha.iToB(h2), sha.iToB(h3), sha.iToB(h4), sha.iToB(h5), sha.iToB(h6), sha.iToB(h7)}
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

func (h *Sha256) iToB(i keccakf.Xuint32) []keccakf.Xuint8 {
	var res []keccakf.Xuint8
	return h.uapi8.EncodeToXuint8From32BigEndian(res, i)
}

func (h *Sha256) rightRotate(n keccakf.Xuint32, shift int) keccakf.Xuint32 {
	return h.uapi32.Rrot(n, shift)
}

func (h *Sha256) rightShift(n keccakf.Xuint32, shift int) keccakf.Xuint32 {
	return h.uapi32.Rshift(n, shift)
}

// https://github.com/akosba/jsnark/blob/master/JsnarkCircuitBuilder/src/examples/gadgets/hash/SHA256Gadget.java
func trimBits(api frontend.API, a frontend.Variable, size int) frontend.Variable {

	requiredSize := 32
	aBits := api.ToBinary(a, size)
	x := make([]frontend.Variable, requiredSize)

	for i := requiredSize; i < size; i++ {
		aBits[i] = 0
	}
	for i := 0; i < requiredSize; i++ {
		x[i] = aBits[i]
	}

	return api.FromBinary(x...)
}
