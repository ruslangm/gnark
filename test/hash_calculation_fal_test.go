package test

import (
	"fmt"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/frontend"
	"github.com/ethereum/go-ethereum/common"
	"testing"
)

type BinaryRepresentationCheckCircuit struct {
	ExpectedResult [256]frontend.Variable
	Hash           frontend.Variable
}

func (circuit BinaryRepresentationCheckCircuit) Define(api frontend.API) error {
	bits := api.ToBinary(circuit.Hash, 256)
	res := [256]frontend.Variable{}

	// take a look that bits are completely equal with witness expected result for successful test
	//and completely different for failed test
	for i := len(bits) - 1; i >= 0; i-- {
		api.Println(bits[i])
	}

	for i, j := len(bits)-1, 0; i >= 0; i, j = i-1, j+1 {
		res[i] = bits[j]
	}

	for i := range res {
		api.AssertIsEqual(res[i], circuit.ExpectedResult[i])
	}
	return nil
}

func TestBinaryRepresentationCircuitSuccess(t *testing.T) {
	var circuit, witness BinaryRepresentationCheckCircuit

	data := common.FromHex("af6b80f7c6b8d2e5ce1cfa3a58c7c8530a7f75bc4f73569a8dcffbde3efc075")
	witness.Hash = data

	setBitsToWitness(data, &witness)

	fmt.Println(witness.ExpectedResult)

	assert := NewAssert(t)
	assert.SolvingSucceeded(
		&circuit,
		&witness,
		WithBackends(backend.GROTH16),
		WithCurves(ecc.BN254),
		WithCompileOpts(frontend.IgnoreUnconstrainedInputs()),
	)
}

func TestBinaryRepresentationCircuitFail(t *testing.T) {
	var circuit, witness BinaryRepresentationCheckCircuit

	// same hash, just number `3` added at the end. both (successful and failed cases) are 32 bytes hashes
	data := common.FromHex("af6b80f7c6b8d2e5ce1cfa3a58c7c8530a7f75bc4f73569a8dcffbde3efc0753")
	witness.Hash = data

	setBitsToWitness(data, &witness)

	fmt.Println(witness.ExpectedResult)

	assert := NewAssert(t)
	assert.SolvingSucceeded(
		&circuit,
		&witness,
		WithBackends(backend.GROTH16),
		WithCurves(ecc.BN254),
		WithCompileOpts(frontend.IgnoreUnconstrainedInputs()),
	)
}

func setBitsToWitness(data []byte, witness *BinaryRepresentationCheckCircuit) {
	for i, b := range data {
		for j := 0; j < 8; j++ {
			witness.ExpectedResult[i*8+(7-j)] = (b >> j) & 1
		}
	}
}
