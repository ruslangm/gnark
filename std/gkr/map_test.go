package gkr_test

import (
	"fmt"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
	"github.com/stretchr/testify/assert"
	"strconv"
	"strings"
	"testing"
)

// TODO: These data structures fail to equate different representations of the same number. i.e. 5 = -10/-2

type Map struct {
	keys   []frontend.Variable
	values []frontend.Variable
}

func getDelta(api frontend.API, x frontend.Variable, deltaIndex int, keys []frontend.Variable) frontend.Variable {
	num := frontend.Variable(1)
	den := frontend.Variable(1)

	for i, key := range keys {
		if i != deltaIndex {
			num = api.Mul(num, api.Sub(key, x))
			den = api.Mul(den, api.Sub(key, keys[deltaIndex]))
		}
	}

	return api.Div(num, den)
}

// Get returns garbage if key is not present
func (m Map) Get(api frontend.API, key frontend.Variable) frontend.Variable {
	res := frontend.Variable(0)

	for i := range m.keys {
		deltaI := getDelta(api, key, i, m.keys)
		res = api.Add(res, api.Mul(deltaI, m.values[i]))
	}

	return res
}

// The keys in a DoubleMap must be constant. i.e. known at setup time
type DoubleMap struct {
	keys1  []frontend.Variable
	keys2  []frontend.Variable
	values [][]frontend.Variable
}

// Get is very inefficient. Do not use outside testing
func (m DoubleMap) Get(api frontend.API, key1, key2 frontend.Variable) frontend.Variable {
	deltas1 := make([]frontend.Variable, len(m.keys1))
	deltas2 := make([]frontend.Variable, len(m.keys2))

	for i := range deltas1 {
		deltas1[i] = getDelta(api, key1, i, m.keys1)
	}

	for j := range deltas2 {
		deltas2[j] = getDelta(api, key2, j, m.keys2)
	}

	res := frontend.Variable(0)

	for i := range deltas1 {
		for j := range deltas2 {
			if m.values[i][j] != nil {
				api.Println(m.keys1[i], m.keys2[j])
				deltaIJ := api.Mul(deltas1[i], deltas2[j], m.values[i][j])
				res = api.Add(res, deltaIJ)
			}
		}
	}

	return res
}

func register[K comparable](m map[K]int, key K) {
	if _, ok := m[key]; !ok {
		m[key] = len(m)
	}
}

func orderKeys[K comparable](order map[K]int) (ordered []K) {
	ordered = make([]K, len(order))
	for k, i := range order {
		ordered[i] = k
	}
	return
}

func ReadMap(in map[string]interface{}) (Map, DoubleMap) {
	single := Map{
		keys:   make([]frontend.Variable, 0),
		values: make([]frontend.Variable, 0),
	}

	keys1 := make(map[string]int)
	keys2 := make(map[string]int)

	for k, v := range in {
		kSep := strings.Split(k, ",")
		switch len(kSep) {
		case 1:
			single.keys = append(single.keys, k)
			single.values = append(single.values, v)
		case 2:

			register(keys1, kSep[0])
			register(keys2, kSep[1])

		default:
			panic("too many keys")
		}
	}

	vals := make([][]frontend.Variable, len(keys1))
	for i := range vals {
		vals[i] = make([]frontend.Variable, len(keys2))
	}

	for k, v := range in {
		kSep := strings.Split(k, ",")
		if len(kSep) == 2 {
			i1 := keys1[kSep[0]]
			i2 := keys2[kSep[1]]
			vals[i1][i2] = v
		}
	}

	double := DoubleMap{
		keys1:  toVariableSlice(orderKeys(keys1)),
		keys2:  toVariableSlice(orderKeys(keys2)),
		values: vals,
	}

	return single, double
}

func getKeys[K comparable, V any](m map[K]V) []K {
	kS := make([]K, len(m))
	i := 0
	for k := range m {
		kS[i] = k
		i++
	}
	return kS
}

func getValuesOrdered[K comparable, V any](m map[K]V, keys []K) []V {
	vS := make([]V, len(keys))
	for i, k := range keys {
		vS[i] = m[k]
	}
	return vS
}

func toVariableSlice[V any](slice []V) (variableSlice []frontend.Variable) {
	variableSlice = make([]frontend.Variable, len(slice))
	for i, v := range slice {
		variableSlice[i] = v
	}
	return
}

type TestSingleMapCircuit struct {
	M      Map `gnark:"-"`
	Values []frontend.Variable
}

func (c *TestSingleMapCircuit) Define(api frontend.API) error {

	for i, k := range c.M.keys {
		v := c.M.Get(api, k)
		api.AssertIsEqual(v, c.Values[i])
	}

	return nil
}

func TestSingleMap(t *testing.T) {
	m := map[string]interface{}{
		"1": -2,
		"4": 1,
		"6": 7,
	}
	single, _ := ReadMap(m)

	assignment := TestSingleMapCircuit{
		M:      single,
		Values: single.values,
	}

	circuit := TestSingleMapCircuit{
		M:      single,
		Values: make([]frontend.Variable, len(m)), // Okay to use the same object?
	}

	assert := test.NewAssert(t)
	assert.ProverSucceeded(&circuit, &assignment, test.WithBackends(backend.GROTH16))
}

type TestDoubleMapCircuit struct {
	M      DoubleMap `gnark:"-"`
	Values []frontend.Variable
	Keys1  []frontend.Variable `gnark:"-"`
	Keys2  []frontend.Variable `gnark:"-"`
}

func (c *TestDoubleMapCircuit) Define(api frontend.API) error {

	for i := range c.Keys1 {
		v := c.M.Get(api, c.Keys1[i], c.Keys2[i])
		api.AssertIsEqual(v, c.Values[i])
	}

	return nil
}

func toMap(keys1, keys2, values []frontend.Variable) map[string]interface{} {
	res := make(map[string]interface{}, len(keys1))
	for i := range keys1 {
		str := strconv.Itoa(keys1[i].(int)) + "," + strconv.Itoa(keys2[i].(int))
		res[str] = values[i].(int)
	}
	return res
}

func TestReadDoubleMap(t *testing.T) {
	keys1 := []frontend.Variable{1, 2}
	keys2 := []frontend.Variable{1, 0}
	values := []frontend.Variable{3, 1}

	for i := 0; i < 100; i++ {
		m := toMap(keys1, keys2, values)
		_, double := ReadMap(m)
		valuesOrdered := [][]frontend.Variable{{3, nil}, {nil, 1}}

		assert.True(t, double.keys1[0] == "1" && double.keys1[1] == "2" || double.keys1[0] == "2" && double.keys1[1] == "1")
		assert.True(t, double.keys2[0] == "1" && double.keys2[1] == "0" || double.keys2[0] == "0" && double.keys2[1] == "1")

		if double.keys1[0] != "1" {
			valuesOrdered[0], valuesOrdered[1] = valuesOrdered[1], valuesOrdered[0]
		}

		if double.keys2[0] != "1" {
			valuesOrdered[0][0], valuesOrdered[0][1] = valuesOrdered[0][1], valuesOrdered[0][0]
			valuesOrdered[1][0], valuesOrdered[1][1] = valuesOrdered[1][1], valuesOrdered[1][0]
		}

		assert.True(t, slice2Eq(valuesOrdered, double.values))

	}

}

func slice2Eq(s1, s2 [][]frontend.Variable) bool {
	if len(s1) != len(s2) {
		return false
	}
	for i := range s1 {
		if !sliceEq(s1[i], s2[i]) {
			return false
		}
	}
	return true
}

func sliceEq(s1, s2 []frontend.Variable) bool {
	if len(s1) != len(s2) {
		return false
	}
	for i := range s1 {
		if s1[i] != s2[i] {
			return false
		}
	}
	return true
}

func TestDoubleMap(t *testing.T) {
	keys1 := []frontend.Variable{1, 5, 5, 3}
	keys2 := []frontend.Variable{1, -5, 4, 4}
	values := []frontend.Variable{0, 2, 3, 0}

	m := toMap(keys1, keys2, values)
	_, double := ReadMap(m)

	fmt.Println(double)

	assignment := TestDoubleMapCircuit{
		M:      double,
		Values: values,
		Keys1:  keys1,
		Keys2:  keys2,
	}

	circuit := TestDoubleMapCircuit{
		M:      double,
		Keys1:  keys1,
		Keys2:  keys2,
		Values: make([]frontend.Variable, len(m)), // Okay to use the same object?
	}

	test.NewAssert(t).ProverSucceeded(&circuit, &assignment, test.WithBackends(backend.GROTH16))
}

func TestDoubleMapManyTimes(t *testing.T) {
	for i := 0; i < 100; i++ {
		TestDoubleMap(t)
	}
}
