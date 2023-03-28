package sha256

import (
	"crypto/sha256"
	"fmt"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/test"
	"github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/assert"
	"testing"
)

type sha256Circuit struct {
	ExpectedResult frontend.Variable
	Data           []frontend.Variable
	CyclesNumber   int
}

func (circuit sha256Circuit) Define(api frontend.API) error {
	for i := 0; i < circuit.CyclesNumber; i++ {
		keccakHash := Sha256Api(api, circuit.Data[:]...)
		api.AssertIsEqual(keccakHash, circuit.ExpectedResult)
	}
	return nil
}

func TestSha256(t *testing.T) {
	var circuit, witness sha256Circuit
	seed := "Hello world!"
	h := sha256.New()
	h.Reset()
	h.Write([]byte(seed))
	output := h.Sum(nil)

	circuit.Data = make([]frontend.Variable, len(seed))
	witness.Data = make([]frontend.Variable, len(seed))
	for j := range seed {
		witness.Data[j] = seed[j]
	}
	fmt.Println(common.Bytes2Hex(output))
	witness.ExpectedResult = output

	witness.CyclesNumber = 1
	circuit.CyclesNumber = 1

	assert := test.NewAssert(t)
	assert.SolvingSucceeded(
		&circuit,
		&witness,
		test.WithBackends(backend.GROTH16),
		test.WithCurves(ecc.BN254),
	)
}

func TestConstraintsSha256(t *testing.T) {
	var circuit, assignment sha256Circuit
	seed := "Hello world!"

	h := sha256.New()
	h.Reset()
	h.Write([]byte(seed))
	output := h.Sum(nil)

	circuit.Data = make([]frontend.Variable, len(seed))
	assignment.Data = make([]frontend.Variable, len(seed))
	for j := range seed {
		assignment.Data[j] = seed[j]
	}
	fmt.Println(common.Bytes2Hex(output))
	assignment.ExpectedResult = output

	i := 1
	assignment.CyclesNumber = i
	circuit.CyclesNumber = i

	ccs, _ := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit, frontend.IgnoreUnconstrainedInputs())
	fmt.Printf("Constraints num=%v\n", ccs.GetNbConstraints())
	ccs.GetNbVariables()

	ccs.Lazify()

	session := "stest"
	pk, vk, _ := groth16.Setup(ccs)
	groth16.SplitDumpPK(pk, session)

	witness, _ := frontend.NewWitness(assignment, bn254.ID.ScalarField())

	pks, err := groth16.ReadSegmentProveKey(session)
	assert.NoError(t, err)

	prf, err := groth16.ProveRoll(ccs, pks[0], pks[1], witness, session)
	assert.NoError(t, err)

	pubWitness, err := witness.Public()
	assert.NoError(t, err)
	err = groth16.Verify(prf, vk, pubWitness)
	assert.NoError(t, err)
}
