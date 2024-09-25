/*
Copyright 2024 Drewbernetes.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package flags

import (
	"fmt"
	"github.com/spf13/viper"
)

// SignOptions contains options for the 'sign' command. These will be available to the subcommands and not configured directly for the sign command itself.
type SignOptions struct {
	BaseOptions
	OpenStackCoreFlags
	SignGenerateOptions

	VaultURL        string
	VaultToken      string
	VaultMountPath  string
	VaultSecretPath string
	ImageID         string
	PrivateKey      string
	PublicKey       string
}

// SetOptionsFromViper configures additional options passed in via viper for the struct from any subcommands.
func (o *SignOptions) SetOptionsFromViper() {
	o.ImageID = viper.GetString(fmt.Sprintf("%s.image-id", viperSignPrefix))
	o.VaultURL = viper.GetString(fmt.Sprintf("%s.url", viperVaultPrefix))
	o.VaultToken = viper.GetString(fmt.Sprintf("%s.token", viperVaultPrefix))
	o.VaultMountPath = viper.GetString(fmt.Sprintf("%s.mount-path", viperVaultPrefix))
	o.VaultSecretPath = viper.GetString(fmt.Sprintf("%s.secret-name", viperVaultPrefix))
	o.PrivateKey = viper.GetString(fmt.Sprintf("%s.private-key", viperSignPrefix))
	o.PublicKey = viper.GetString(fmt.Sprintf("%s.public-key", viperSignPrefix))

	o.BaseOptions.SetOptionsFromViper()
	o.OpenStackCoreFlags.SetOptionsFromViper()
	o.SignGenerateOptions.SetOptionsFromViper()
}

// SignGenerateOptions contains additional options for the 'generate' subcommand.
type SignGenerateOptions struct {
	Path string
}

// SetOptionsFromViper configures options passed in via viper for the struct.
func (o *SignGenerateOptions) SetOptionsFromViper() {
	o.Path = viper.GetString(fmt.Sprintf("%s.path", viperGeneratePrefix))
}
