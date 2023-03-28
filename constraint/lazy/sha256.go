package lazy

import (
	"github.com/consensys/gnark/constraint"
	"strconv"
)

func init() {
	err := RegisterSha256Factory()
	if err != nil {
		panic(err)
	}
}

func GetLazySha256Key(params int) string {
	return "sha256-params-" + strconv.Itoa(params)
}

func RegisterSha256Factory() error {
	key := GetLazySha256Key(64)
	constraint.Register(key, createGeneralLazyInputsFunc(key))
	return nil
}
