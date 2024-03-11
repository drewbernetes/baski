package interfaces

import (
	"github.com/drewbernetes/baski/pkg/util/flags"
	"github.com/gophercloud/gophercloud"
	"github.com/gophercloud/gophercloud/openstack/compute/v2/extensions/keypairs"
	"github.com/gophercloud/gophercloud/openstack/compute/v2/servers"
	"github.com/gophercloud/gophercloud/openstack/imageservice/v2/images"
	"github.com/gophercloud/gophercloud/openstack/networking/v2/extensions/layer3/floatingips"
)

//go:generate mockgen -source=openstack.go -destination=../../mock/openstack.go -package=mock

type OpenStackClient interface {
	Client() (*gophercloud.ProviderClient, error)
}

type OpenStackComputeClient interface {
	CreateKeypair(keyNamePrefix string) (*keypairs.KeyPair, error)
	RemoveKeypair(keyName string) error
	CreateServer(keypairName string, flavor, networkID string, attachConfigDrive *bool, userData []byte, imageID string, securityGroups []string) (*servers.Server, error)
	GetServerStatus(sid string) (bool, error)
	AttachIP(serverID, fip string) error
	RemoveServer(serverID string) error
	GetFlavorIDByName(name string) (string, error)
}

type OpenStackImageClient interface {
	ModifyImageMetadata(imgID string, key, value string, operation images.UpdateOp) (*images.Image, error)
	FetchAllImages(wildcard string) ([]images.Image, error)
	RemoveImage(imgID string) error
	FetchImage(imgID string) (*images.Image, error)
	TagImage(properties map[string]interface{}, imgID, value, tagName string) error
	ChangeImageVisibility(imgID string, visibility images.ImageVisibility) error
}

type OpenStackNetworkClient interface {
	GetFloatingIP(networkName string) (*floatingips.FloatingIP, error)
	RemoveFIP(fipID string) error
}

type OpenStackScannerInterface interface {
	RunScan(o *flags.ScanOptions) error
	FetchScanResults() error
	CheckResults() error
	TagImage() error
	UploadResultsToS3() error
}
