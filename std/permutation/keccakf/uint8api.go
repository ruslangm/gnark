package keccakf

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/bits"
)

// Uint8api performs binary operations on Xuint8 variables.
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
		res[i] = 0
	}
	for i := range res {
		for _, v := range in {
			res[i] = w.api.Or(res[i], v[i])
		}
	}
	return res
}

func (w *Uint8api) assertEq(a, b Xuint8) {
	for i := range a {
		w.api.AssertIsEqual(a[i], b[i])
	}
}

func DecodeToXuint64(b []Xuint8) Xuint64 {
	var res Xuint64
	for i := range res {
		res[i] = 0
	}
	d := b[:8]
	for i := len(res) - 1; i >= 0; {
		for _, v := range d {
			for z := range v {
				res[i] = v[len(d)-1-z]
				i -= 1
			}
		}
	}
	return res
}

func EncodeToXuint8(b []Xuint8, x Xuint64) []Xuint8 {
	var res [8]Xuint8
	for i, v := range res {
		for j := range v {
			res[i][j] = 0
		}
	}

	byteIdx := 0
	for i := 0; i < len(res); i++ {
		for j := range res[i] {
			//log.Printf("64idx=%v,8btidx=%v,btidx=%v\n\n", byteIdx, i, j)
			res[i][j] = x[byteIdx]
			byteIdx += 1
		}
	}

	return append(b, res[0], res[1], res[2], res[3], res[4], res[5], res[6], res[7])
}
