package flags

import (
	"fmt"
	"github.com/spf13/viper"
)

type BaseOptions struct {
	InfraType string
}

func (o *BaseOptions) SetOptionsFromViper() {
	o.InfraType = viper.GetString(fmt.Sprintf("%s.type", viperInfraPrefix))
}
