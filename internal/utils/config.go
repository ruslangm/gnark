package utils

import "github.com/consensys/gnark/std/gkr/circuit"

type GkrInfo struct {
	bN       int
	circuits []circuit.Circuit
}

func NewGkrInfo(bN int, circuit []circuit.Circuit) *GkrInfo {
	return &GkrInfo{bN: bN, circuits: circuit}
}

func (g *GkrInfo) getBN() int {
	return g.bN
}

func (g *GkrInfo) getCircuits() []circuit.Circuit {
	return g.circuits
}
