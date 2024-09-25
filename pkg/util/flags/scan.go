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

type ScanOptions struct {
	BaseOptions
	OpenStackFlags
	KubeVirtFlags
	S3Flags
	ScanSingleOptions
	ScanMultipleOptions

	ScanFlavorName      string
	AutoDeleteImage     bool
	SkipCVECheck        bool
	MaxSeverityScore    float64
	MaxSeverityType     string
	ScanBucket          string
	TrivyignorePath     string
	TrivyignoreFilename string
	TrivyignoreList     []string
}

func (o *ScanOptions) SetOptionsFromViper() {
	o.AutoDeleteImage = viper.GetBool(fmt.Sprintf("%s.auto-delete-image", viperScanPrefix))
	o.SkipCVECheck = viper.GetBool(fmt.Sprintf("%s.skip-cve-check", viperScanPrefix))
	o.MaxSeverityScore = viper.GetFloat64(fmt.Sprintf("%s.max-severity-score", viperScanPrefix))
	o.MaxSeverityType = viper.GetString(fmt.Sprintf("%s.max-severity-type", viperScanPrefix))
	o.ScanBucket = viper.GetString(fmt.Sprintf("%s.scan-bucket", viperScanPrefix))
	o.TrivyignorePath = viper.GetString(fmt.Sprintf("%s.trivyignore-path", viperScanPrefix))
	o.TrivyignoreFilename = viper.GetString(fmt.Sprintf("%s.trivyignore-filename", viperScanPrefix))
	o.TrivyignoreList = viper.GetStringSlice(fmt.Sprintf("%s.trivyignore-list", viperScanPrefix))

	o.BaseOptions.SetOptionsFromViper()
	o.OpenStackFlags.SetOptionsFromViper()
	o.KubeVirtFlags.SetOptionsFromViper()
	o.S3Flags.SetOptionsFromViper()
	o.ScanSingleOptions.SetOptionsFromViper()
	o.ScanMultipleOptions.SetOptionsFromViper()

	// We can override the value of the instance at the scan level
	// This isn't available in the flags as it's already a flag that's available. This is viper only.
	instance := viper.GetString(fmt.Sprintf("%s.flavor-name", viperScanPrefix))
	if instance != "" {
		o.FlavorName = instance
	}
}

type ScanSingleOptions struct {
	ImageID string
}

func (o *ScanSingleOptions) SetOptionsFromViper() {
	o.ImageID = viper.GetString(fmt.Sprintf("%s.image-id", viperSinglePrefix))
}

type ScanMultipleOptions struct {
	ImageSearch string
	Concurrency int
}

func (o *ScanMultipleOptions) SetOptionsFromViper() {
	o.Concurrency = viper.GetInt(fmt.Sprintf("%s.concurrency", viperMultiplePrefix))
	o.ImageSearch = viper.GetString(fmt.Sprintf("%s.image-search", viperMultiplePrefix))
}
