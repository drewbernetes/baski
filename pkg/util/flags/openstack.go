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

// OpenStackCoreFlags are the core requirements for any interaction with the openstack cloud.
type OpenStackCoreFlags struct {
	CloudsPath     string
	CloudName      string
	MetadataPrefix string
}

// SetOptionsFromViper configures additional options passed in via viper for the struct.
func (o *OpenStackCoreFlags) SetOptionsFromViper() {
	o.CloudsPath = viper.GetString(fmt.Sprintf("%s.clouds-file", viperOpenStackPrefix))
	o.CloudName = viper.GetString(fmt.Sprintf("%s.cloud-name", viperOpenStackPrefix))
	o.MetadataPrefix = viper.GetString(fmt.Sprintf("%s.metadata-prefix", viperOpenStackPrefix))

}

// OpenStackInstanceFlags are Additional flags that can would be required for other steps such as scan, sign and publish.
type OpenStackInstanceFlags struct {
	AttachConfigDrive bool
	NetworkID         string
	FlavorName        string
}

// SetOptionsFromViper configures additional options passed in via viper for the struct.
func (o *OpenStackInstanceFlags) SetOptionsFromViper() {
	o.NetworkID = viper.GetString(fmt.Sprintf("%s.network-id", viperOpenStackPrefix))
	o.FlavorName = viper.GetString(fmt.Sprintf("%s.flavor-name", viperOpenStackPrefix))
	o.AttachConfigDrive = viper.GetBool(fmt.Sprintf("%s.attach-config-drive", viperOpenStackPrefix))
}

// OpenStackFlags are explicitly for OpenStack based clouds and defines settings that pertain only to that cloud type.
type OpenStackFlags struct {
	OpenStackCoreFlags
	OpenStackInstanceFlags

	SourceImageID         string
	SSHPrivateKeyFile     string
	SSHKeypairName        string
	UseFloatingIP         bool
	FloatingIPNetworkName string
	SecurityGroup         string
	ImageVisibility       string
	ImageDiskFormat       string
	UseBlockStorageVolume string
	VolumeType            string
	VolumeSize            int
}

// SetOptionsFromViper configures additional options passed in via viper for the struct.
func (q *OpenStackFlags) SetOptionsFromViper() {
	q.SourceImageID = viper.GetString(fmt.Sprintf("%s.source-image", viperOpenStackPrefix))
	q.SSHPrivateKeyFile = viper.GetString(fmt.Sprintf("%s.ssh-privatekey-file", viperOpenStackPrefix))
	q.SSHKeypairName = viper.GetString(fmt.Sprintf("%s.ssh-keypair-name", viperOpenStackPrefix))
	q.UseFloatingIP = viper.GetBool(fmt.Sprintf("%s.use-floating-ip", viperOpenStackPrefix))
	q.FloatingIPNetworkName = viper.GetString(fmt.Sprintf("%s.floating-ip-network-name", viperOpenStackPrefix))
	q.SecurityGroup = viper.GetString(fmt.Sprintf("%s.security-group", viperOpenStackPrefix))
	q.ImageVisibility = viper.GetString(fmt.Sprintf("%s.image-visibility", viperOpenStackPrefix))
	q.ImageDiskFormat = viper.GetString(fmt.Sprintf("%s.image-disk-format", viperOpenStackPrefix))
	q.UseBlockStorageVolume = viper.GetString(fmt.Sprintf("%s.use-blockstorage-volume", viperOpenStackPrefix))
	q.VolumeType = viper.GetString(fmt.Sprintf("%s.volume-type", viperOpenStackPrefix))
	q.VolumeSize = viper.GetInt(fmt.Sprintf("%s.volume-size", viperOpenStackPrefix))

	q.OpenStackCoreFlags.SetOptionsFromViper()
	q.OpenStackInstanceFlags.SetOptionsFromViper()
}
