package keccakf

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/bits"
)

// Uint64api performs binary operations on Xuint8 variables. In the
// future possibly using lookup tables.
//
// TODO: we could possibly optimise using hints if working over many inputs. For
// example, if we OR many bits, then the result is 0 if the sum of the bits is
// larger than 1. And AND is 1 if the sum of bits is the number of inputs. BUt
// this probably helps only if we have a lot of similar operations in a row
// (more than 4). We could probably unroll the whole permutation and expand all
// the formulas to see. But long term tables are still better.
type Uint8api struct {
	api frontend.API
}

func NewUint8API(api frontend.API) *Uint8api {
	return &Uint8api{
		api: api,
	}
}

// varUint64 represents 64-bit unsigned integer. We use this type to ensure that
// we work over constrained bits. Do not initialize directly, use [wideBinaryOpsApi.asUint64].
type Xuint8 [8]frontend.Variable

func ConstUint8(a uint8) Xuint8 {
	var res Xuint8
	for i := 0; i < 8; i++ {
		res[i] = (a >> i) & 1
	}
	return res
}

func (w *Uint8api) AsUint8FromBytes(in ...frontend.Variable) Xuint8 {
	return w.AsUint8(bits.FromBinary(w.api, in))
}

func (w *Uint8api) AsUint8(in frontend.Variable) Xuint8 {
	bits := bits.ToBinary(w.api, in, bits.WithNbDigits(8))
	var res Xuint8
	copy(res[:], bits)
	return res
}

func (w *Uint8api) FromUint8(in Xuint8) frontend.Variable {
	return bits.FromBinary(w.api, in[:], bits.WithUnconstrainedInputs())
}

func (w *Uint8api) And(in ...Xuint8) Xuint8 {
	var res Xuint8
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

func (w *Uint8api) Or(in ...Xuint8) Xuint8 {
	var res Xuint8
	for i := range res {
		res[i] = 1
	}
	for i := range res {
		for _, v := range in {
			res[i] = w.api.Or(res[i], v[i])
		}
	}
	return res
}

func (w *Uint8api) Xor(in ...Xuint8) Xuint8 {
	var res Xuint8
	for i := range res {
		res[i] = 0
	}
	for i := range res {
		for _, v := range in {
			res[i] = w.api.Xor(res[i], v[i])
		}
	}
	return res
}

func (w *Uint8api) Lrot(in Xuint8, shift int) Xuint8 {
	var res Xuint8
	for i := range res {
		res[i] = in[(i-shift+8)%8]
	}
	return res
}

func (w *Uint8api) not(in Xuint8) Xuint8 {
	// TODO: it would be better to have separate method for it. If we have
	// native API support, then in R1CS would be free (1-X) and in PLONK 1
	// constraint (1-X). But if we do XOR, then we always have a constraint with
	// R1CS (not sure if 1-2 with PLONK). If we do 1-X ourselves, then compiler
	// marks as binary which is 1-2 (R1CS-PLONK).
	var res Xuint8
	for i := range res {
		res[i] = w.api.Xor(in[i], 1)
	}
	return res
}

func (w *Uint8api) assertEq(a, b Xuint8) {
	for i := range a {
		w.api.AssertIsEqual(a[i], b[i])
	}
}
