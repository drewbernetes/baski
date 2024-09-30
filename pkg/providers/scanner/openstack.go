package scanner

import (
	"encoding/json"
	"errors"
	"fmt"
	sshconnect "github.com/drewbernetes/baski/pkg/remote"
	"github.com/drewbernetes/baski/pkg/trivy"
	"github.com/drewbernetes/baski/pkg/util/flags"
	"github.com/drewbernetes/baski/pkg/util/interfaces"
	simple_s3 "github.com/drewbernetes/simple-s3"
	"github.com/gophercloud/gophercloud/openstack/compute/v2/extensions/keypairs"
	"github.com/gophercloud/gophercloud/openstack/compute/v2/servers"
	"github.com/gophercloud/gophercloud/openstack/imageservice/v2/images"
	"github.com/gophercloud/gophercloud/openstack/networking/v2/extensions/layer3/floatingips"
	"log"
	"os"
	"strings"
	"time"
)

type OpenStackScannerClient struct {
	BaseScanner
	Img *images.Image

	computeClient interfaces.OpenStackComputeClient
	imageClient   interfaces.OpenStackImageClient
	networkClient interfaces.OpenStackNetworkClient
	keyPair       *keypairs.KeyPair
	fip           *floatingips.FloatingIP
	s3Credentials *simple_s3.S3
	server        *servers.Server
	severity      trivy.Severity
}

// NewOpenStackScanner returns new scanner client.
func NewOpenStackScanner(c interfaces.OpenStackComputeClient, i interfaces.OpenStackImageClient, n interfaces.OpenStackNetworkClient, s3Conn *simple_s3.S3, severity trivy.Severity, img *images.Image) *OpenStackScannerClient {
	return &OpenStackScannerClient{
		computeClient: c,
		imageClient:   i,
		networkClient: n,
		s3Credentials: s3Conn,
		severity:      severity,
		Img:           img,
	}
}

// RunScan builds the server for scanning and starts the scan
func (s *OpenStackScannerClient) RunScan(o *flags.ScanOptions) error {
	trivyOptions := trivy.New(o.TrivyignorePath, o.TrivyignoreFilename, o.TrivyignoreList, s.severity)
	err := s.getKeypair(s.Img.ID)
	if err != nil {
		return err
	}
	err = s.getFip(o.OpenStackFlags.FloatingIPNetworkName)
	if err != nil {
		fmt.Println(err)
		return err
	}

	userData, err := trivyOptions.GenerateTrivyCommand(s.s3Credentials)
	if err != nil {
		return err
	}

	err = s.buildServer(o.OpenStackInstanceFlags.FlavorName, o.OpenStackInstanceFlags.NetworkID, s.Img.ID, o.OpenStackInstanceFlags.AttachConfigDrive, userData, []string{o.OpenStackFlags.SecurityGroup})
	if err != nil {
		return err
	}
	return nil
}

func (s *OpenStackScannerClient) FetchScanResults() error {
	//TODO: We need to capture-ctl c and cleanup resources if it's hit.
	client, err := sshconnect.NewSSHClient("ubuntu", s.keyPair.PrivateKey, s.fip.FloatingIP, "22")
	if err != nil {
		return err
	}

	err = fetchResultsFromServer(client, s.Img.ID)
	if err != nil {
		e := removeOpenStackResources(s.server.ID, s.keyPair.Name, s.fip, s.computeClient, s.networkClient)
		if e != nil {
			return e
		}
		return err
	}

	//Close SSH & SFTP connection
	err = client.SFTPClose()
	if err != nil {
		return err
	}
	err = client.SSHClose()
	if err != nil {
		return err
	}

	// Cleanup the scanning resources
	e := removeOpenStackResources(s.server.ID, s.keyPair.Name, s.fip, s.computeClient, s.networkClient)
	if e != nil {
		return e
	}
	return nil
}

// CheckResults checks the results file for vulnerabilitie-s and parses it into a more friendly format.
func (s *OpenStackScannerClient) CheckResults() error {
	var err error
	j := []byte("{}")

	s.MetaTag = "passed"
	s.ResultsFile = fmt.Sprintf("/tmp/%s.json", s.Img.ID)
	s.Vulns, err = parsingVulnerabilities(s.ResultsFile)
	if err != nil {
		return err
	}
	if len(s.Vulns) != 0 {
		j, err = json.Marshal(s.Vulns)
		if err != nil {
			return errors.New("couldn't marshall vulnerability trivyIgnoreFile: " + err.Error())
		}
		s.MetaTag = "failed"
	}

	// write the vulnerabilities into the results file
	err = os.WriteFile(s.ResultsFile, j, os.FileMode(0644))
	if err != nil {
		return errors.New("couldn't write vulnerability trivyIgnoreFile to file: " + err.Error())
	}

	return nil
}

// TagImage Tags the image with the passed or failed property.
func (s *OpenStackScannerClient) TagImage(metadataPrefix string) error {
	tag := "security_scan"
	if metadataPrefix != "" {
		tag = strings.Join([]string{metadataPrefix, tag}, ":")
	}
	err := s.imageClient.TagImage(s.Img.Properties, s.Img.ID, s.MetaTag, tag)
	if err != nil {
		return err
	}

	return nil
}

// UploadResultsToS3 uploads the scan results to S3.
func (s *OpenStackScannerClient) UploadResultsToS3() error {
	//Upload results to S3
	f, err := os.Open(s.ResultsFile)
	if err != nil {
		return err
	}
	defer f.Close()

	err = s.s3Credentials.Put(fmt.Sprintf("scans/%s/%s", s.Img.ID, "results.json"), f)
	if err != nil {
		return err
	}

	return nil
}

func (s *OpenStackScannerClient) getKeypair(imgID string) error {
	kp, err := s.computeClient.CreateKeypair(imgID)
	if err != nil {
		return err
	}
	s.keyPair = kp
	return nil
}

func (s *OpenStackScannerClient) getFip(fipNetworkName string) error {
	fip, err := s.networkClient.GetFloatingIP(fipNetworkName)
	if err != nil {
		e := s.computeClient.RemoveKeypair(s.keyPair.Name)
		if e != nil {
			return e
		}
		return err
	}
	s.fip = fip
	return nil
}

// buildServer is responsible for building the server
func (s *OpenStackScannerClient) buildServer(flavor, networkID, imgID string, attachConfigDrive bool, userData []byte, securityGroups []string) error {
	server, err := s.computeClient.CreateServer(s.keyPair.Name, flavor, networkID, &attachConfigDrive, userData, imgID, securityGroups)
	if err != nil {
		e := s.computeClient.RemoveKeypair(s.keyPair.Name)
		if e != nil {
			return e
		}
		e = s.networkClient.RemoveFIP(s.fip.ID)
		if e != nil {
			return e
		}
		return err
	}

	state, err := s.computeClient.GetServerStatus(server.ID)
	if err != nil {
		e := removeOpenStackResources(server.ID, s.keyPair.Name, s.fip, s.computeClient, s.networkClient)
		if e != nil {
			return e
		}
		return err
	}
	checkLimit := 0
	for !state {
		if checkLimit > 100 {
			panic(errors.New("server failed to come online after 500 seconds"))
		}
		log.Println("server not active, waiting 5 seconds and then checking again")
		time.Sleep(5 * time.Second)
		state, err = s.computeClient.GetServerStatus(server.ID)
		if err != nil {
			e := removeOpenStackResources(server.ID, s.keyPair.Name, s.fip, s.computeClient, s.networkClient)
			if e != nil {
				return e
			}
			return err
		}
		checkLimit++
	}

	err = s.computeClient.AttachIP(server.ID, s.fip.FloatingIP)
	if err != nil {
		e := removeOpenStackResources(server.ID, s.keyPair.Name, s.fip, s.computeClient, s.networkClient)
		if e != nil {
			return e
		}
		return err
	}

	s.server = server

	return nil
}

// removeOpenStackResources cleans up the server and keypair from Openstack to ensure nothing is left lying around.
func removeOpenStackResources(serverID, keyName string, fip *floatingips.FloatingIP, c interfaces.OpenStackComputeClient, n interfaces.OpenStackNetworkClient) error {
	err := c.RemoveServer(serverID)
	if err != nil {
		return err
	}
	err = c.RemoveKeypair(keyName)
	if err != nil {
		return err
	}
	err = n.RemoveFIP(fip.ID)
	if err != nil {
		return err
	}
	return nil
}
