package keccak

import (
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
	"testing"
)

type keccak256Circuit struct {
	ExpectedResult [32]frontend.Variable
	Data           []frontend.Variable
}

type testcase struct {
	msg    []byte
	output []byte
}

func (circuit keccak256Circuit) Define(api frontend.API) error {
	keccak256 := NewKeccak256(api)
	keccak256.Reset()
	keccak256.Write(circuit.Data[:]...)
	result := keccak256.Sum(nil)
	for i := range result {
		api.AssertIsEqual(result[i], circuit.ExpectedResult[i])
	}
	return nil
}

func TestKeccakShort256(t *testing.T) {
	var circuit, witness keccak256Circuit
	for i := range tstShort {
		seed := tstShort[i].msg
		output := tstShort[i].output
		circuit.Data = make([]frontend.Variable, len(seed))
		witness.Data = make([]frontend.Variable, len(seed))
		for j := range seed {
			witness.Data[j] = seed[j]
		}
		for j := range output {
			witness.ExpectedResult[j] = output[j]
		}

		assert := test.NewAssert(t)
		assert.SolvingSucceeded(
			&circuit,
			&witness,
			test.WithBackends(backend.GROTH16),
			test.WithCurves(ecc.BN254),
		)
	}
}
