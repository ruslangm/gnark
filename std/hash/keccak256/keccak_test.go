package keccak

import (
	"bytes"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
	"github.com/ethereum/go-ethereum/crypto"
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

func TestKeccak256Short(t *testing.T) {
	var circuit, witness keccak256Circuit
	for i := range testCaseShort {
		seed := testCaseShort[i].msg
		output := testCaseShort[i].output
		outputCryptoEth := crypto.Keccak256Hash(seed).Bytes()

		if !bytes.Equal(output, outputCryptoEth) {
			t.Errorf("Keccak256 testcase Short %d: expected %x got %x", i, testCaseShort[i].output, outputCryptoEth)
		}

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

func TestKeccak256Long(t *testing.T) {
	var circuit, witness keccak256Circuit
	for i := range testCaseLong {
		seed := testCaseLong[i].msg
		output := testCaseLong[i].output
		outputCryptoEth := crypto.Keccak256Hash(seed).Bytes()

		if !bytes.Equal(output, outputCryptoEth) {
			t.Errorf("Keccak256 testcase Long %d: expected %x got %x", i, testCaseLong[i].output, outputCryptoEth)
		}

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
