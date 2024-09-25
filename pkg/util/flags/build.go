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

type BuildOptions struct {
	BaseOptions
	KubernetesClusterFlags
	S3Flags
	OpenStackFlags
	KubeVirtFlags

	Verbose                 bool
	BuildOS                 string
	ImagePrefix             string
	ImageRepo               string
	ImageRepoBranch         string
	ImageRepoDir            string
	ContainerdSHA256        string
	ContainerdVersion       string
	CrictlVersion           string
	CniVersion              string
	CniDebVersion           string
	KubeVersion             string
	KubeRpmVersion          string
	KubeDebVersion          string
	ExtraDebs               string
	AdditionalImages        []string
	AdditionalMetadata      map[string]string
	AddFalco                bool
	AddTrivy                bool
	AddGpuSupport           bool
	GpuVendor               string
	GpuModelSupport         string
	GpuInstanceSupport      string
	AMDVersion              string
	AMDDebVersion           string
	AMDUseCase              string
	NvidiaVersion           string
	NvidiaBucket            string
	NvidiaInstallerLocation string
	NvidiaTOKLocation       string
	NvidiaGriddFeatureType  int
}

func (o *BuildOptions) SetOptionsFromViper() {
	// General Flags
	o.Verbose = viper.GetBool(fmt.Sprintf("%s.verbose", viperBuildPrefix))
	o.BuildOS = viper.GetString(fmt.Sprintf("%s.build-os", viperBuildPrefix))
	o.ImagePrefix = viper.GetString(fmt.Sprintf("%s.image-prefix", viperBuildPrefix))
	o.ImageRepo = viper.GetString(fmt.Sprintf("%s.image-repo", viperBuildPrefix))
	o.ImageRepoBranch = viper.GetString(fmt.Sprintf("%s.image-repo-branch", viperBuildPrefix))
	o.ImageRepoDir = viper.GetString(fmt.Sprintf("%s.image-repo-dir", viperBuildPrefix))
	o.ContainerdSHA256 = viper.GetString(fmt.Sprintf("%s.containerd-sha256", viperBuildPrefix))
	o.ContainerdVersion = viper.GetString(fmt.Sprintf("%s.containerd-version", viperBuildPrefix))
	o.CrictlVersion = viper.GetString(fmt.Sprintf("%s.crictl-version", viperBuildPrefix))
	o.CniVersion = viper.GetString(fmt.Sprintf("%s.cni-version", viperBuildPrefix))
	o.CniDebVersion = viper.GetString(fmt.Sprintf("%s.cni-deb-version", viperBuildPrefix))
	o.KubeVersion = viper.GetString(fmt.Sprintf("%s.kubernetes-version", viperBuildPrefix))
	o.KubeDebVersion = viper.GetString(fmt.Sprintf("%s.kubernetes-deb-version", viperBuildPrefix))
	o.KubeRpmVersion = viper.GetString(fmt.Sprintf("%s.kubernetes-rpm-version", viperBuildPrefix))
	o.ExtraDebs = viper.GetString(fmt.Sprintf("%s.extra-debs", viperBuildPrefix))
	o.AdditionalImages = viper.GetStringSlice(fmt.Sprintf("%s.additional-images", viperBuildPrefix))
	o.AdditionalMetadata = viper.GetStringMapString(fmt.Sprintf("%s.additional-metadata", viperBuildPrefix))
	o.AddFalco = viper.GetBool(fmt.Sprintf("%s.add-falco", viperBuildPrefix))
	o.AddTrivy = viper.GetBool(fmt.Sprintf("%s.add-trivy", viperBuildPrefix))

	// GPU
	o.AddGpuSupport = viper.GetBool(fmt.Sprintf("%s.enable-gpu-support", viperGpuPrefix))
	o.GpuVendor = viper.GetString(fmt.Sprintf("%s.gpu-vendor", viperGpuPrefix))
	o.GpuModelSupport = viper.GetString(fmt.Sprintf("%s.gpu-model-support", viperGpuPrefix))
	o.GpuInstanceSupport = viper.GetString(fmt.Sprintf("%s.gpu-instance-support", viperGpuPrefix))
	// AMD
	o.AMDVersion = viper.GetString(fmt.Sprintf("%s.amd-driver-version", viperGpuPrefix))
	o.AMDDebVersion = viper.GetString(fmt.Sprintf("%s.amd-deb-version", viperGpuPrefix))
	o.AMDUseCase = viper.GetString(fmt.Sprintf("%s.amd-usecase", viperGpuPrefix))
	// NVIDIA
	o.NvidiaVersion = viper.GetString(fmt.Sprintf("%s.nvidia-driver-version", viperGpuPrefix))
	o.NvidiaBucket = viper.GetString(fmt.Sprintf("%s.nvidia-bucket", viperGpuPrefix))
	o.NvidiaInstallerLocation = viper.GetString(fmt.Sprintf("%s.nvidia-installer-location", viperGpuPrefix))
	o.NvidiaTOKLocation = viper.GetString(fmt.Sprintf("%s.nvidia-tok-location", viperGpuPrefix))
	o.NvidiaGriddFeatureType = viper.GetInt(fmt.Sprintf("%s.nvidia-gridd-feature-type", viperGpuPrefix))

	o.BaseOptions.SetOptionsFromViper()
	o.KubernetesClusterFlags.SetOptionsFromViper()
	o.S3Flags.SetOptionsFromViper()
	o.OpenStackFlags.SetOptionsFromViper()
	o.KubeVirtFlags.SetOptionsFromViper()
}
