package keccak

import (
	"bytes"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
	"golang.org/x/crypto/sha3"
	"math/big"
	"testing"
)

type keccak256Circuit struct {
	ExpectedResult [32]frontend.Variable `gnark:"data,public"`
	Data           [32]frontend.Variable
}

func (circuit keccak256Circuit) Define(api frontend.API) error {
	keccak256 := NewKeccak256(api)
	keccak256.Reset()
	keccak256.Write(circuit.Data[:]...)
	result := keccak256.Sum()
	api.AssertIsEqual(result, circuit.ExpectedResult)
	return nil
}

func TestKeccak256(t *testing.T) {
	var buf bytes.Buffer
	seed := new(big.Int).SetInt64(10000)
	seedBytes := seed.FillBytes(make([]byte, 32))
	buf.Write(seedBytes)
	assert := test.NewAssert(t)

	hash := sha3.NewLegacyKeccak256()
	_, _ = hash.Write(buf.Bytes())
	val := hash.Sum(nil)

	var circuit, witness keccak256Circuit
	for i := range val {
		witness.ExpectedResult[i] = val[i]
	}
	witness.Data = [32]frontend.Variable{}
	for i := range seedBytes {
		witness.Data[i] = seedBytes[i]
	}

	assert.SolvingSucceeded(
		&circuit,
		&witness,
		test.WithBackends(backend.GROTH16),
		test.WithCurves(ecc.BN254),
	)
}
