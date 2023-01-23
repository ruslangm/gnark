package keccak

import (
	"bytes"
	"fmt"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"testing"
	"time"
)

type keccak256Circuit struct {
	ExpectedResult frontend.Variable
	Data           []frontend.Variable
}

type testcase struct {
	msg    []byte
	output []byte
}

func (circuit keccak256Circuit) Define(api frontend.API) error {
	keccakHash := Keccak256Api(api, circuit.Data[:]...)
	api.AssertIsEqual(keccakHash, circuit.ExpectedResult)
	return nil
}

func TestKeccak256(t *testing.T) {
	var circuit, witness keccak256Circuit
	seed := "abc"
	output := crypto.Keccak256Hash([]byte(seed)).Bytes()

	circuit.Data = make([]frontend.Variable, len(seed))
	witness.Data = make([]frontend.Variable, len(seed))
	for j := range seed {
		witness.Data[j] = seed[j]
	}
	fmt.Println(common.Bytes2Hex(output))
	witness.ExpectedResult = output

	assert := test.NewAssert(t)
	assert.SolvingSucceeded(
		&circuit,
		&witness,
		test.WithBackends(backend.GROTH16),
		test.WithCurves(ecc.BN254),
	)
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
		witness.ExpectedResult = output

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
	for i := len(testCaseLong) - 1; i >= 0; i-- {
		start := time.Now()
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
		witness.ExpectedResult = output

		assert := test.NewAssert(t)
		assert.SolvingSucceeded(
			&circuit,
			&witness,
			test.WithBackends(backend.GROTH16),
			test.WithCurves(ecc.BN254),
		)
		fmt.Printf("time passed for i=%v: %v", i, time.Since(start))
	}
}
