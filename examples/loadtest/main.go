// Copyright 2020 ConsenSys AG
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"fmt"
	"github.com/DmitriyVTitov/size"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	bn254r1cs "github.com/consensys/gnark/constraint/bn254"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	groth16_bn254 "github.com/consensys/gnark/internal/backend/bn254/groth16"
	"github.com/consensys/gnark/std/hash/mimc"
	"log"
	"os"
	"runtime"
)

// In this example we show how to use PLONK with KZG commitments. The circuit that is

// Circuit defines a pre-image knowledge proof
// mimc(secret preImage) = public hash
type Circuit struct {
	// struct tag on a variable is optional
	// default uses variable name and secret visibility.
	PreImage frontend.Variable
	Hash     frontend.Variable `gnark:",public"`
}

// Define declares the circuit's constraints
// Hash = mimc(PreImage)
func (circuit *Circuit) Define(api frontend.API) error {
	for i := 0; i < 10000; i++ {
		mimc, _ := mimc.NewMiMC(api)
		mimc.Write(circuit.PreImage)
		api.AssertIsEqual(circuit.Hash, mimc.Sum())
	}

	return nil
}
func main() {

	var circuit Circuit

	// // building the circuit...
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)
	if err != nil {
		fmt.Println("circuit compilation error")
	}
	fmt.Println("cs size:", ccs.GetNbConstraints())

	// Correct data: the proof passes
	{
		// Witnesses instantiation. Witness is known only by the prover,
		// while public w is a public data known by the verifier.
		var w Circuit
		w.PreImage = "16130099170765464552823636852555369511329944820189892919423002775646948828469"
		w.Hash = "12886436712380113721405259596386800092738845035233065858332878701083870690753"

		witnessFull, err := frontend.NewWitness(&w, ecc.BN254.ScalarField())
		if err != nil {
			log.Fatal(err)
		}

		witnessPublic, err := frontend.NewWitness(&w, ecc.BN254.ScalarField(), frontend.PublicOnly())
		if err != nil {
			log.Fatal(err)
		}

		// public data consists the polynomials describing the constants involved
		// in the constraints, the polynomial describing the permutation ("grand
		// product argument"), and the FFT domains.
		fmt.Println("setup...")
		pk, vk, err := groth16.Setup(ccs)
		//_, err := plonk.Setup(r1cs, kate, &publicWitness)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println("size of pk:", size.Of(pk))
		pk2 := pk.(*groth16_bn254.ProvingKey)
		fmt.Println("size of pk:", size.Of(pk2))

		fmt.Println("r1cs dump")
		r1csDump, _ := os.Create("r1cs.dump")
		_, _ = ccs.WriteTo(r1csDump)
		r1csDump.Close()

		fmt.Println("r1cs load")
		r1csDump, _ = os.Open("r1cs.dump")
		ccs2 := groth16.NewCS(ecc.BN254)
		_, _ = ccs2.ReadFrom(r1csDump)
		fmt.Println("r1cs load finished")
		ccs3 := ccs2.(*bn254r1cs.R1CS)

		fmt.Println("size of ccs3:", size.Of(ccs3))
		fmt.Println("size of ccs3.system:", size.Of(ccs3.R1CSCore.System))
		fmt.Println("size of ccs3.constraints:", size.Of(ccs3.R1CSCore.Constraints))
		groth16.SplitDumpR1CS(ccs3, "LoadTestFoo", 10000)
		ccs33 := groth16.LoadSplittedR1CSConcurrent("LoadTestFoo", len(ccs3.Constraints), 10000, runtime.NumCPU())
		fmt.Println("size of ccs33:", size.Of(ccs33))
		fmt.Println("size of ccs33.system:", size.Of(ccs33.R1CSCore.System))
		fmt.Println("size of ccs33.constraints:", size.Of(ccs33.R1CSCore.Constraints))

		proof, err := groth16.Prove(ccs33, pk, witnessFull)
		if err != nil {
			log.Fatal(err)
		}

		err = groth16.Verify(proof, vk, witnessPublic)
		if err != nil {
			log.Fatal(err)
		}
	}

}
