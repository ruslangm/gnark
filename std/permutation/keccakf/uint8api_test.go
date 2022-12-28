package keccakf

import (
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"testing"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
)

type andUint8Circ struct {
	In1 frontend.Variable
	In2 frontend.Variable
	Out frontend.Variable
}

type orUint8Circ struct {
	In1 frontend.Variable
	In2 frontend.Variable
	Out frontend.Variable
}

type uint8ToUint64Circ struct {
	In  []frontend.Variable
	Out frontend.Variable
}

func (c *andUint8Circ) Define(api frontend.API) error {
	uapi := NewUint8API(api)
	in1 := uapi.AsUint8(c.In1)
	in2 := uapi.AsUint8(c.In2)
	out := uapi.AsUint8(c.Out)
	res := uapi.And(in1, in2)
	uapi.assertEq(out, res)
	return nil
}

func (c *orUint8Circ) Define(api frontend.API) error {
	uapi := NewUint8API(api)
	in1 := uapi.AsUint8(c.In1)
	in2 := uapi.AsUint8(c.In2)
	out := uapi.AsUint8(c.Out)
	res := uapi.Or(in1, in2)
	uapi.assertEq(out, res)
	return nil
}

func (c uint8ToUint64Circ) Define(api frontend.API) error {
	uapi := NewUint8API(api)
	uapi64 := NewUint64API(api)

	in := make([]Xuint8, len(c.In))
	for i, v := range c.In {
		in[i] = uapi.AsUint8(v)
	}
	res := DecodeToXuint64(in)

	out := uapi64.AsUint64(c.Out)
	uapi64.assertEq(out, res)
	return nil
}

func TestAndOperation(t *testing.T) {
	assert := test.NewAssert(t)
	assert.ProverSucceeded(&andUint8Circ{In1: 2, In2: 6, Out: 2}, &andUint8Circ{In1: 2, In2: 6, Out: 2})
}

func TestOrOperation(t *testing.T) {
	assert := test.NewAssert(t)
	assert.ProverSucceeded(&orUint8Circ{In1: 2, In2: 6, Out: 6}, &orUint8Circ{In1: 2, In2: 6, Out: 6})
}

func TestDecodeUint8ToUint64Operation(t *testing.T) {
	assert := test.NewAssert(t)
	in := []frontend.Variable{8, 7, 6, 5, 4, 3, 2, 1}

	var circuit, witness uint8ToUint64Circ
	witness.In = in
	witness.Out = 15
	assert.SolvingSucceeded(
		&circuit,
		&witness,
		test.WithBackends(backend.GROTH16),
		test.WithCurves(ecc.BN254))
}
