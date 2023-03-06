package gkr

import (
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/internal/backend/bn254/cs"
	bn254witness "github.com/consensys/gnark/internal/backend/bn254/witness"
	"reflect"
)

func witnessGenerator(id ecc.ID, inputs [][]fr.Element, bN, batchSize, initialLength int) (results []fr.Element, startLength, endLength int) {
	nativeCircuits := CreateMimcCircuitBatch(batchSize)
	for i := range nativeCircuits {
		nativeCircuit := nativeCircuits[i]
		assignment := nativeCircuit.Assign(inputs, 1)
		outputs := assignment.Values[batchSize]
		prover := NewProver(nativeCircuit, assignment)
		proofg := prover.Prove(1)
		qInitialprime, _ := GetInitialQPrimeAndQAndInput(bN, 0, inputs[0])
		c := AllocateGKRMimcTestCircuitBatch(bN, i)
		c.Assign(proofg, inputs, outputs, qInitialprime)

		for i := range inputs {
			for j := range inputs[i] {
				// copy gate should stay with initial inputs
				// cipher gate needs to copy
				if j < len(inputs[i])/2 {
					inputs[i][j] = outputs[i][j/2]
				}
			}
		}

		w, err := witness.New(id, nil)
		if err != nil {
			panic(err)
		}

		tVariable := reflect.ValueOf(struct{ A frontend.Variable }{}).FieldByName("A").Type()
		w.Schema, err = w.Vector.FromAssignment(&c, tVariable, false)
		if err != nil {
			panic(err)
		}

		// first start len
		if startLength == 0 {
			startLength = initialLength - w.Vector.Len()*(7-i)
		}
		witnessToSolution := *w.Vector.(*bn254witness.Witness)
		for j := initialLength - w.Vector.Len()*(7-i); j < initialLength-w.Vector.Len()*(6-i); j++ {
			results = append(results, witnessToSolution[j-initialLength+w.Vector.Len()*(7-i)])
		}
		endLength = initialLength - w.Vector.Len()*(6-i)
	}
	return results, startLength, endLength
}

func init() {
	cs.RegisterGKRWitnessGeneratorHandler(witnessGenerator)
}
