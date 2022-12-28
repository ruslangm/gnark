package keccakf

import (
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

func TestAndOperation(t *testing.T) {
	assert := test.NewAssert(t)
	assert.ProverSucceeded(&andUint8Circ{In1: 2, In2: 6, Out: 2}, &andUint8Circ{In1: 2, In2: 6, Out: 2})
}

func TestOrOperation(t *testing.T) {
	assert := test.NewAssert(t)
	assert.ProverSucceeded(&orUint8Circ{In1: 2, In2: 6, Out: 6}, &orUint8Circ{In1: 2, In2: 6, Out: 6})
}
