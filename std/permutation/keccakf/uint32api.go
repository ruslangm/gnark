package keccakf

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/bits"
)

// Uint8api performs binary operations on Xuint8 variables.
type Uint32api struct {
	api frontend.API
}

func NewUint32API(api frontend.API) *Uint32api {
	return &Uint32api{
		api: api,
	}
}

// Xuint32 represents 32-bit byte. We use this type to ensure that
// we work over constrained bits.
type Xuint32 [32]frontend.Variable

func ConstUint32(a uint32) Xuint32 {
	var res Xuint32
	for i := 0; i < 32; i++ {
		res[i] = (a >> i) & 1
	}
	return res
}

func (w *Uint32api) FromUint64(in Xuint32) frontend.Variable {
	return bits.FromBinary(w.api, in[:], bits.WithUnconstrainedInputs())
}

func (w *Uint32api) AsUint32(in frontend.Variable) Xuint32 {
	bits := bits.ToBinary(w.api, in, bits.WithNbDigits(32))
	var res Xuint32
	copy(res[:], bits)
	return res
}

func (w *Uint32api) FromUint32(in Xuint32) frontend.Variable {
	return bits.FromBinary(w.api, in[:], bits.WithUnconstrainedInputs())
}

func (w *Uint32api) FromUint32BE(in Xuint32) frontend.Variable {
	res := [32]frontend.Variable{}
	for i := range res {
		res[i] = in[len(in)-1-i]
	}
	return bits.FromBinary(w.api, res[:], bits.WithUnconstrainedInputs())
}

func (w *Uint32api) And(in ...Xuint32) Xuint32 {
	var res Xuint32
	for i := range res {
		res[i] = 1
	}
	for i := range res {
		for _, v := range in {
			res[i] = w.api.And(res[i], v[i])
		}
	}
	return res
}

func (w *Uint32api) Not(in Xuint32) Xuint32 {
	var res Xuint32
	for i := range res {
		res[i] = w.api.Xor(in[i], 1)
	}
	return res
}

func (w *Uint32api) Xor(in ...Xuint32) Xuint32 {
	var res Xuint32
	for i := range res {
		res[i] = 0
	}
	for i := range res {
		for _, v := range in {
			if v[i] != nil {
				res[i] = w.api.Xor(res[i], v[i])
			}
		}
	}
	return res
}

func (w *Uint32api) Or(in ...Xuint32) Xuint32 {
	var res Xuint32
	for i := range res {
		res[i] = 0
	}
	for i := range res {
		for _, v := range in {
			res[i] = w.api.Or(res[i], v[i])
		}
	}
	return res
}

func (w *Uint32api) Rrot(in Xuint32, shift int) Xuint32 {
	var res Xuint32
	for i := range res {
		res[i] = in[(i+shift)%32]
	}
	return res
}

func (w *Uint32api) Rshift(in Xuint32, shift int) Xuint32 {
	var res Xuint32
	for i := range res {
		res[i] = 0
	}
	for i := range res {
		if i+shift < 32 {
			res[i] = in[i+shift]
		}
	}
	return res
}

func (w *Uint32api) assertEq(a, b Xuint32) {
	for i := range a {
		w.api.AssertIsEqual(a[i], b[i])
	}
}
