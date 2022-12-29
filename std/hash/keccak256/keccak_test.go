package keccak

import (
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
	"golang.org/x/crypto/sha3"
	"math/big"
	"testing"
)

type keccak256Circuit struct {
	ExpectedResult [32]frontend.Variable
	Data           [32]frontend.Variable
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

func TestKeccak256(t *testing.T) {
	seed := new(big.Int).SetInt64(123456)
	seedBytes := seed.FillBytes(make([]byte, 32))

	hash := sha3.NewLegacyKeccak256()
	_, _ = hash.Write(seedBytes)
	val := hash.Sum(nil)

	var circuit, witness keccak256Circuit
	witness.Data = [32]frontend.Variable{}
	for i := range seedBytes {
		witness.Data[i] = seedBytes[i]
	}
	for i := range val {
		witness.ExpectedResult[i] = val[i]
	}

	assert := test.NewAssert(t)
	assert.SolvingSucceeded(
		&circuit,
		&witness,
		test.WithBackends(backend.GROTH16),
		test.WithCurves(ecc.BN254),
	)
}
