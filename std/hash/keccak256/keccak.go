package keccak

import (
	"fmt"
	"github.com/consensys/gnark/frontend"
	keccakf2 "github.com/consensys/gnark/std/permutation/keccakf"
)

const Size = 256 / 8

const BlockSize = 1600/8 - Size*2

// Keccak256 implements hash.Hash
// variable == single byte
type Keccak256 struct {
	a      [25]keccakf2.Xuint64
	buf    [200]keccakf2.Xuint8
	dsbyte keccakf2.Xuint8
	len    int
	size   int
	api    frontend.API
	uapi64 *keccakf2.Uint64api
	uapi8  *keccakf2.Uint8api
}

func (h *Keccak256) Api() frontend.API {
	return h.api
}

func NewKeccak256(api frontend.API) Keccak256 {
	return Keccak256{
		dsbyte: keccakf2.ConstUint8(0x01),
		size:   256 / 8,
		api:    api,
		uapi64: keccakf2.NewUint64API(api),
		uapi8:  keccakf2.NewUint8API(api),
	}
}

func (h *Keccak256) Size() int      { return h.size }
func (h *Keccak256) BlockSize() int { return BlockSize }

func (h *Keccak256) Reset() {
	h.a = [25]keccakf2.Xuint64{}
	for i := range h.a {
		h.a[i] = keccakf2.ConstUint64(0)
	}
	h.buf = [200]keccakf2.Xuint8{}
	h.len = 0
}

func (h *Keccak256) Write(data ...frontend.Variable) {
	bs := h.BlockSize()

	in := make([]keccakf2.Xuint8, len(data))
	for i := range data {
		in[i] = h.uapi8.AsUint8(data[i])
	}

	for len(data) > 0 {
		n := copy(h.buf[h.len:bs], in)
		h.len += n
		data = data[n:]
		/* for every block Pi in P */
		if h.len == bs {
			h.flush()
		}
	}
}

func (h *Keccak256) flush() {
	b := h.buf[:h.len]
	for i := range h.a {
		if len(b) == 0 {
			break
		}
		/* S[x, y] = S[x, y] ⊕ Pi[x + 5y],   ∀(x, y) such that x + 5y < r/w */
		piUint64 := h.decodeToXuint64(b)
		h.a[i] = h.uapi64.Xor(h.a[i], piUint64)
		fmt.Printf("Updated value of h.a[%v] with b=%v\n", i, piUint64)
		b = b[8:]
	}
	h.keccakf()
	h.len = 0
}

func (h *Keccak256) keccakf() {
	in := [25]frontend.Variable{}
	for i := range h.a {
		in[i] = h.uapi64.FromUint64(h.a[i])
	}
	keccakf2.Permute(h.api, in)
}

func (h *Keccak256) Sum(data ...frontend.Variable) []frontend.Variable {
	d := *h
	d.buf[d.len] = h.uapi8.AsUint8(0x01)
	bs := d.BlockSize()
	for i := d.len + 1; i < bs; i++ {
		d.buf[i] = h.uapi8.AsUint8(0x00)
	}
	d.buf[bs-1] = h.uapi8.Or(d.buf[bs-1], h.uapi8.AsUint8(0x80))
	d.len = bs

	d.flush()

	var res []keccakf2.Xuint8
	for i := 0; i < d.size/8; i++ {
		res = h.encodeToXuint8(res, d.a[i])
	}

	r := make([]frontend.Variable, len(res))
	for i := range res {
		r[i] = h.uapi8.FromUint8(res[i])
	}
	return r
}

func (h *Keccak256) decodeToXuint64(b []keccakf2.Xuint8) keccakf2.Xuint64 {
	var res keccakf2.Xuint64
	for i := range res {
		res[i] = 0
	}
	for i := len(res) - 1; i >= 0; i -= len(b) {
		for j := range b {
			res[i] = h.uapi8.FromUint8(b[len(b)-j-1])
		}
	}
	return res
}

func (h *Keccak256) encodeToXuint8(b []keccakf2.Xuint8, x keccakf2.Xuint64) []keccakf2.Xuint8 {
	var res [8]keccakf2.Xuint8
	for i, v := range res {
		for j := range v {
			res[i][j] = 0
		}
	}

	for i, v := range res {
		for j := range v {
			res[i][j] = x[i+j]
		}
	}

	return append(b, res[0], res[1], res[2], res[3], res[4], res[5], res[6], res[7])
}
