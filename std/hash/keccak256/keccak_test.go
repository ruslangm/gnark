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
	ExpectedResult frontend.Variable `gnark:"data,public"`
	Data           frontend.Variable
}

func (circuit *keccak256Circuit) Define(api frontend.API) error {
	keccak256 := NewKeccak256(api)
	keccak256.Reset()
	keccak256.Write(circuit.Data)
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
	witness.ExpectedResult = val
	witness.Data = seedBytes

	assert.SolvingSucceeded(
		&circuit,
		&witness,
		test.WithBackends(backend.GROTH16),
		test.WithCurves(ecc.BN254),
		test.WithCompileOpts(frontend.IgnoreUnconstrainedInputs()))
}
