// +build !providerless

/*
Copyright 2016 The Kubernetes Authors.

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

package vsphere

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"io/ioutil"
	"log"
	"net/url"
	"os"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/vmware/govmomi/find"
	lookup "github.com/vmware/govmomi/lookup/simulator"
	"github.com/vmware/govmomi/property"
	"github.com/vmware/govmomi/simulator"
	"github.com/vmware/govmomi/simulator/vpx"
	sts "github.com/vmware/govmomi/sts/simulator"
	"github.com/vmware/govmomi/vapi/rest"
	vapi "github.com/vmware/govmomi/vapi/simulator"
	"github.com/vmware/govmomi/vapi/tags"
	"github.com/vmware/govmomi/vim25/mo"
	vmwaretypes "github.com/vmware/govmomi/vim25/types"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/rand"
	"k8s.io/klog/v2"

	cloudprovider "k8s.io/cloud-provider"
	"k8s.io/legacy-cloud-providers/vsphere/vclib"
)

// localhostCert was generated from crypto/tls/generate_cert.go with the following command:
//     go run generate_cert.go  --rsa-bits 2048 --host 127.0.0.1,::1,example.com --ca --start-date "Jan 1 00:00:00 1970" --duration=1000000h
var localhostCert = `-----BEGIN CERTIFICATE-----
MIIDGDCCAgCgAwIBAgIQTKCKn99d5HhQVCLln2Q+eTANBgkqhkiG9w0BAQsFADAS
MRAwDgYDVQQKEwdBY21lIENvMCAXDTcwMDEwMTAwMDAwMFoYDzIwODQwMTI5MTYw
MDAwWjASMRAwDgYDVQQKEwdBY21lIENvMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A
MIIBCgKCAQEA1Z5/aTwqY706M34tn60l8ZHkanWDl8mM1pYf4Q7qg3zA9XqWLX6S
4rTYDYCb4stEasC72lQnbEWHbthiQE76zubP8WOFHdvGR3mjAvHWz4FxvLOTheZ+
3iDUrl6Aj9UIsYqzmpBJAoY4+vGGf+xHvuukHrVcFqR9ZuBdZuJ/HbbjUyuNr3X9
erNIr5Ha17gVzf17SNbYgNrX9gbCeEB8Z9Ox7dVuJhLDkpF0T/B5Zld3BjyUVY/T
cukU4dTVp6isbWPvCMRCZCCOpb+qIhxEjJ0n6tnPt8nf9lvDl4SWMl6X1bH+2EFa
a8R06G0QI+XhwPyjXUyCR8QEOZPCR5wyqQIDAQABo2gwZjAOBgNVHQ8BAf8EBAMC
AqQwEwYDVR0lBAwwCgYIKwYBBQUHAwEwDwYDVR0TAQH/BAUwAwEB/zAuBgNVHREE
JzAlggtleGFtcGxlLmNvbYcEfwAAAYcQAAAAAAAAAAAAAAAAAAAAATANBgkqhkiG
9w0BAQsFAAOCAQEAThqgJ/AFqaANsOp48lojDZfZBFxJQ3A4zfR/MgggUoQ9cP3V
rxuKAFWQjze1EZc7J9iO1WvH98lOGVNRY/t2VIrVoSsBiALP86Eew9WucP60tbv2
8/zsBDSfEo9Wl+Q/gwdEh8dgciUKROvCm76EgAwPGicMAgRsxXgwXHhS5e8nnbIE
Ewaqvb5dY++6kh0Oz+adtNT5OqOwXTIRI67WuEe6/B3Z4LNVPQDIj7ZUJGNw8e6L
F4nkUthwlKx4yEJHZBRuFPnO7Z81jNKuwL276+mczRH7piI6z9uyMV/JbEsOIxyL
W6CzB7pZ9Nj1YLpgzc1r6oONHLokMJJIz/IvkQ==
-----END CERTIFICATE-----`

// localhostKey is the private key for localhostCert.
// Fake value for testing.
var localhostKey = `-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA1Z5/aTwqY706M34tn60l8ZHkanWDl8mM1pYf4Q7qg3zA9XqW
LX6S4rTYDYCb4stEasC72lQnbEWHbthiQE76zubP8WOFHdvGR3mjAvHWz4FxvLOT
heZ+3iDUrl6Aj9UIsYqzmpBJAoY4+vGGf+xHvuukHrVcFqR9ZuBdZuJ/HbbjUyuN
r3X9erNIr5Ha17gVzf17SNbYgNrX9gbCeEB8Z9Ox7dVuJhLDkpF0T/B5Zld3BjyU
VY/TcukU4dTVp6isbWPvCMRCZCCOpb+qIhxEjJ0n6tnPt8nf9lvDl4SWMl6X1bH+
2EFaa8R06G0QI+XhwPyjXUyCR8QEOZPCR5wyqQIDAQABAoIBAFAJmb1pMIy8OpFO
hnOcYWoYepe0vgBiIOXJy9n8R7vKQ1X2f0w+b3SHw6eTd1TLSjAhVIEiJL85cdwD
MRTdQrXA30qXOioMzUa8eWpCCHUpD99e/TgfO4uoi2dluw+pBx/WUyLnSqOqfLDx
S66kbeFH0u86jm1hZibki7pfxLbxvu7KQgPe0meO5/13Retztz7/xa/pWIY71Zqd
YC8UckuQdWUTxfuQf0470lAK34GZlDy9tvdVOG/PmNkG4j6OQjy0Kmz4Uk7rewKo
ZbdphaLPJ2A4Rdqfn4WCoyDnxlfV861T922/dEDZEbNWiQpB81G8OfLL+FLHxyIT
LKEu4R0CgYEA4RDj9jatJ/wGkMZBt+UF05mcJlRVMEijqdKgFwR2PP8b924Ka1mj
9zqWsfbxQbdPdwsCeVBZrSlTEmuFSQLeWtqBxBKBTps/tUP0qZf7HjfSmcVI89WE
3ab8LFjfh4PtK/LOq2D1GRZZkFliqi0gKwYdDoK6gxXWwrumXq4c2l8CgYEA8vrX
dMuGCNDjNQkGXx3sr8pyHCDrSNR4Z4FrSlVUkgAW1L7FrCM911BuGh86FcOu9O/1
Ggo0E8ge7qhQiXhB5vOo7hiVzSp0FxxCtGSlpdp4W6wx6ZWK8+Pc+6Moos03XdG7
MKsdPGDciUn9VMOP3r8huX/btFTh90C/L50sH/cCgYAd02wyW8qUqux/0RYydZJR
GWE9Hx3u+SFfRv9aLYgxyyj8oEOXOFjnUYdY7D3KlK1ePEJGq2RG81wD6+XM6Clp
Zt2di0pBjYdi0S+iLfbkaUdqg1+ImLoz2YY/pkNxJQWQNmw2//FbMsAJxh6yKKrD
qNq+6oonBwTf55hDodVHBwKBgEHgEBnyM9ygBXmTgM645jqiwF0v75pHQH2PcO8u
Q0dyDr6PGjiZNWLyw2cBoFXWP9DYXbM5oPTcBMbfizY6DGP5G4uxzqtZHzBE0TDn
OKHGoWr5PG7/xDRrSrZOfe3lhWVCP2XqfnqoKCJwlOYuPws89n+8UmyJttm6DBt0
mUnxAoGBAIvbR87ZFXkvqstLs4KrdqTz4TQIcpzB3wENukHODPA6C1gzWTqp+OEe
GMNltPfGCLO+YmoMQuTpb0kECYV3k4jR3gXO6YvlL9KbY+UOA6P0dDX4ROi2Rklj
yh+lxFLYa1vlzzi9r8B7nkR9hrOGMvkfXF42X89g7lx4uMtu2I4q
-----END RSA PRIVATE KEY-----`

func configFromEnv() (cfg VSphereConfig, ok bool) {
	var InsecureFlag bool
	var err error
	cfg.Global.VCenterIP = os.Getenv("VSPHERE_VCENTER")
	cfg.Global.VCenterPort = os.Getenv("VSPHERE_VCENTER_PORT")
	cfg.Global.User = os.Getenv("VSPHERE_USER")
	cfg.Global.Password = os.Getenv("VSPHERE_PASSWORD")
	cfg.Global.Datacenter = os.Getenv("VSPHERE_DATACENTER")
	cfg.Network.PublicNetwork = os.Getenv("VSPHERE_PUBLIC_NETWORK")
	cfg.Global.DefaultDatastore = os.Getenv("VSPHERE_DATASTORE")
	cfg.Disk.SCSIControllerType = os.Getenv("VSPHERE_SCSICONTROLLER_TYPE")
	cfg.Global.WorkingDir = os.Getenv("VSPHERE_WORKING_DIR")
	cfg.Global.VMName = os.Getenv("VSPHERE_VM_NAME")
	if os.Getenv("VSPHERE_INSECURE") != "" {
		InsecureFlag, err = strconv.ParseBool(os.Getenv("VSPHERE_INSECURE"))
	} else {
		InsecureFlag = false
	}
	if err != nil {
		log.Fatal(err)
	}
	cfg.Global.InsecureFlag = InsecureFlag

	ok = (cfg.Global.VCenterIP != "" &&
		cfg.Global.User != "")

	return
}

// configFromSim starts a vcsim instance and returns config for use against the vcsim instance.
// The vcsim instance is configured with an empty tls.Config.
func configFromSim() (VSphereConfig, func()) {
	return configFromSimWithTLS(new(tls.Config), true)
}

// configFromSimWithTLS starts a vcsim instance and returns config for use against the vcsim instance.
// The vcsim instance is configured with a tls.Config. The returned client
// config can be configured to allow/decline insecure connections.
func configFromSimWithTLS(tlsConfig *tls.Config, insecureAllowed bool) (VSphereConfig, func()) {
	var cfg VSphereConfig
	model := simulator.VPX()

	err := model.Create()
	if err != nil {
		log.Fatal(err)
	}

	model.Service.TLS = tlsConfig
	s := model.Service.NewServer()

	// STS simulator
	path, handler := sts.New(s.URL, vpx.Setting)
	model.Service.ServeMux.Handle(path, handler)

	// vAPI simulator
	path, handler = vapi.New(s.URL, vpx.Setting)
	model.Service.ServeMux.Handle(path, handler)

	// Lookup Service simulator
	model.Service.RegisterSDK(lookup.New())

	cfg.Global.InsecureFlag = insecureAllowed

	cfg.Global.VCenterIP = s.URL.Hostname()
	cfg.Global.VCenterPort = s.URL.Port()
	cfg.Global.User = s.URL.User.Username()
	cfg.Global.Password, _ = s.URL.User.Password()
	cfg.Global.Datacenter = vclib.TestDefaultDatacenter
	cfg.Network.PublicNetwork = vclib.TestDefaultNetwork
	cfg.Global.DefaultDatastore = vclib.TestDefaultDatastore
	cfg.Disk.SCSIControllerType = os.Getenv("VSPHERE_SCSICONTROLLER_TYPE")
	cfg.Global.WorkingDir = os.Getenv("VSPHERE_WORKING_DIR")
	cfg.Global.VMName = os.Getenv("VSPHERE_VM_NAME")

	if cfg.Global.WorkingDir == "" {
		cfg.Global.WorkingDir = "vm" // top-level Datacenter.VmFolder
	}

	uuid := simulator.Map.Any("VirtualMachine").(*simulator.VirtualMachine).Config.Uuid
	getVMUUID = func() (string, error) { return uuid, nil }

	return cfg, func() {
		getVMUUID = GetVMUUID
		s.Close()
		model.Remove()
	}
}

// configFromEnvOrSim returns config from configFromEnv if set, otherwise returns configFromSim.
func configFromEnvOrSim() (VSphereConfig, func()) {
	cfg, ok := configFromEnv()
	if ok {
		return cfg, func() {}
	}
	return configFromSim()
}

func TestReadConfig(t *testing.T) {
	_, err := readConfig(nil)
	if err == nil {
		t.Errorf("Should fail when no config is provided: %s", err)
	}

	// Fake values for testing.
	cfg, err := readConfig(strings.NewReader(`
[Global]
server = 0.0.0.0
port = 443
user = user
password = password
insecure-flag = true
datacenter = us-west
vm-uuid = 1234
vm-name = vmname
ca-file = /some/path/to/a/ca.pem
`))
	if err != nil {
		t.Fatalf("Should succeed when a valid config is provided: %s", err)
	}

	if cfg.Global.VCenterIP != "0.0.0.0" {
		t.Errorf("incorrect vcenter ip: %s", cfg.Global.VCenterIP)
	}

	if cfg.Global.Datacenter != "us-west" {
		t.Errorf("incorrect datacenter: %s", cfg.Global.Datacenter)
	}

	if cfg.Global.VMUUID != "1234" {
		t.Errorf("incorrect vm-uuid: %s", cfg.Global.VMUUID)
	}

	if cfg.Global.VMName != "vmname" {
		t.Errorf("incorrect vm-name: %s", cfg.Global.VMName)
	}

	if cfg.Global.CAFile != "/some/path/to/a/ca.pem" {
		t.Errorf("incorrect ca-file: %s", cfg.Global.CAFile)
	}
}

func TestNewVSphere(t *testing.T) {
	cfg, ok := configFromEnv()
	if !ok {
		t.Skipf("No config found in environment")
	}

	_, err := newControllerNode(cfg)
	if err != nil {
		t.Fatalf("Failed to construct/authenticate vSphere: %s", err)
	}
}

func TestVSphereLogin(t *testing.T) {
	cfg, cleanup := configFromEnvOrSim()
	defer cleanup()

	// Create vSphere configuration object
	vs, err := newControllerNode(cfg)
	if err != nil {
		t.Fatalf("Failed to construct/authenticate vSphere: %s", err)
	}

	// Create context
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Create vSphere client
	vcInstance, ok := vs.vsphereInstanceMap[cfg.Global.VCenterIP]
	if !ok {
		t.Fatalf("Couldn't get vSphere instance: %s", cfg.Global.VCenterIP)
	}

	err = vcInstance.conn.Connect(ctx)
	if err != nil {
		t.Errorf("Failed to connect to vSphere: %s", err)
	}
	vcInstance.conn.Logout(ctx)
}

func TestVSphereLoginByToken(t *testing.T) {
	cfg, cleanup := configFromSim()
	defer cleanup()

	// Configure for SAML token auth
	cfg.Global.User = localhostCert
	cfg.Global.Password = localhostKey

	// Create vSphere configuration object
	vs, err := newControllerNode(cfg)
	if err != nil {
		t.Fatalf("Failed to construct/authenticate vSphere: %s", err)
	}

	ctx := context.Background()

	// Create vSphere client
	vcInstance, ok := vs.vsphereInstanceMap[cfg.Global.VCenterIP]
	if !ok {
		t.Fatalf("Couldn't get vSphere instance: %s", cfg.Global.VCenterIP)
	}

	err = vcInstance.conn.Connect(ctx)
	if err != nil {
		t.Errorf("Failed to connect to vSphere: %s", err)
	}
	vcInstance.conn.Logout(ctx)
}

func TestVSphereLoginWithCaCert(t *testing.T) {
	caCertPEM, err := os.ReadFile("./vclib/testdata/ca.pem")
	if err != nil {
		t.Fatalf("Could not read ca cert from file")
	}

	serverCert, err := tls.LoadX509KeyPair("./vclib/testdata/server.pem", "./vclib/testdata/server.key")
	if err != nil {
		t.Fatalf("Could not load server cert and server key from files: %#v", err)
	}

	certPool := x509.NewCertPool()
	if ok := certPool.AppendCertsFromPEM(caCertPEM); !ok {
		t.Fatalf("Cannot add CA to CAPool")
	}

	tlsConfig := tls.Config{
		Certificates: []tls.Certificate{serverCert},
		RootCAs:      certPool,
	}

	cfg, cleanup := configFromSimWithTLS(&tlsConfig, false)
	defer cleanup()

	cfg.Global.CAFile = "./vclib/testdata/ca.pem"

	// Create vSphere configuration object
	vs, err := newControllerNode(cfg)
	if err != nil {
		t.Fatalf("Failed to construct/authenticate vSphere: %s", err)
	}

	ctx := context.Background()

	// Create vSphere client
	vcInstance, ok := vs.vsphereInstanceMap[cfg.Global.VCenterIP]
	if !ok {
		t.Fatalf("Couldn't get vSphere instance: %s", cfg.Global.VCenterIP)
	}

	err = vcInstance.conn.Connect(ctx)
	if err != nil {
		t.Errorf("Failed to connect to vSphere: %s", err)
	}
	vcInstance.conn.Logout(ctx)
}

func TestZonesNoConfig(t *testing.T) {
	_, ok := new(VSphere).Zones()
	if ok {
		t.Fatalf("Zones() should return false without VCP configured")
	}
}

func TestZones(t *testing.T) {
	// Any context will do
	ctx := context.Background()

	// Create a vcsim instance
	cfg, cleanup := configFromSim()
	defer cleanup()

	// Configure for SAML token auth
	cfg.Global.User = localhostCert
	cfg.Global.Password = localhostKey

	// Create vSphere configuration object
	vs, err := newControllerNode(cfg)
	if err != nil {
		t.Fatalf("Failed to construct/authenticate vSphere: %s", err)
	}

	// Configure region and zone categories
	vs.cfg.Labels.Region = "k8s-region"
	vs.cfg.Labels.Zone = "k8s-zone"

	// Create vSphere client
	vsi, ok := vs.vsphereInstanceMap[cfg.Global.VCenterIP]
	if !ok {
		t.Fatalf("Couldn't get vSphere instance: %s", cfg.Global.VCenterIP)
	}

	err = vsi.conn.Connect(ctx)
	if err != nil {
		t.Errorf("Failed to connect to vSphere: %s", err)
	}

	// Lookup Datacenter for this test's Workspace
	dc, err := vclib.GetDatacenter(ctx, vsi.conn, vs.cfg.Workspace.Datacenter)
	if err != nil {
		t.Fatal(err)
	}

	// Lookup VM's host where we'll attach tags
	host, err := dc.GetHostByVMUUID(ctx, vs.vmUUID)
	if err != nil {
		t.Fatal(err)
	}

	// Property Collector instance
	pc := property.DefaultCollector(vsi.conn.Client)

	// Tag manager instance
	m := tags.NewManager(rest.NewClient(vsi.conn.Client))
	signer, err := vsi.conn.Signer(ctx, vsi.conn.Client)
	if err != nil {
		t.Fatal(err)
	}
	if err = m.LoginByToken(m.WithSigner(ctx, signer)); err != nil {
		t.Fatal(err)
	}

	// Create a region category
	regionID, err := m.CreateCategory(ctx, &tags.Category{Name: vs.cfg.Labels.Region})
	if err != nil {
		t.Fatal(err)
	}

	// Create a region tag
	regionID, err = m.CreateTag(ctx, &tags.Tag{CategoryID: regionID, Name: "k8s-region-US"})
	if err != nil {
		t.Fatal(err)
	}

	// Create a zone category
	zoneID, err := m.CreateCategory(ctx, &tags.Category{Name: vs.cfg.Labels.Zone})
	if err != nil {
		t.Fatal(err)
	}

	// Create a zone tag
	zoneID, err = m.CreateTag(ctx, &tags.Tag{CategoryID: zoneID, Name: "k8s-zone-US-CA1"})
	if err != nil {
		t.Fatal(err)
	}

	// Create a random category
	randomID, err := m.CreateCategory(ctx, &tags.Category{Name: "random-cat"})
	if err != nil {
		t.Fatal(err)
	}

	// Create a random tag
	randomID, err = m.CreateTag(ctx, &tags.Tag{CategoryID: randomID, Name: "random-tag"})
	if err != nil {
		t.Fatal(err)
	}

	// Attach a random tag to VM's host
	if err = m.AttachTag(ctx, randomID, host); err != nil {
		t.Fatal(err)
	}

	// Expecting Zones() to return true, indicating VCP supports the Zones interface
	zones, ok := vs.Zones()
	if !ok {
		t.Fatalf("zones=%t", ok)
	}

	// GetZone() tests, covering error and success paths
	tests := []struct {
		name string // name of the test for logging
		fail bool   // expect GetZone() to return error if true
		prep func() // prepare vCenter state for the test
	}{
		{"no tags", true, func() {
			// no prep
		}},
		{"no zone tag", true, func() {
			if err = m.AttachTag(ctx, regionID, host); err != nil {
				t.Fatal(err)
			}
		}},
		{"host tags set", false, func() {
			if err = m.AttachTag(ctx, zoneID, host); err != nil {
				t.Fatal(err)
			}
		}},
		{"host tags removed", true, func() {
			if err = m.DetachTag(ctx, zoneID, host); err != nil {
				t.Fatal(err)
			}
			if err = m.DetachTag(ctx, regionID, host); err != nil {
				t.Fatal(err)
			}
		}},
		{"dc region, cluster zone", false, func() {
			var h mo.HostSystem
			if err = pc.RetrieveOne(ctx, host.Reference(), []string{"parent"}, &h); err != nil {
				t.Fatal(err)
			}
			// Attach region tag to Datacenter
			if err = m.AttachTag(ctx, regionID, dc); err != nil {
				t.Fatal(err)
			}
			// Attach zone tag to Cluster
			if err = m.AttachTag(ctx, zoneID, h.Parent); err != nil {
				t.Fatal(err)
			}
		}},
	}

	for _, test := range tests {
		test.prep()

		zone, err := zones.GetZone(ctx)
		if test.fail {
			if err == nil {
				t.Errorf("%s: expected error", test.name)
			} else {
				t.Logf("%s: expected error=%s", test.name, err)
			}
		} else {
			if err != nil {
				t.Errorf("%s: %s", test.name, err)
			}
			t.Logf("zone=%#v", zone)
		}
	}
}

func TestGetZoneToHosts(t *testing.T) {
	// Common setup for all testcases in this test
	ctx := context.TODO()

	// Create a vcsim instance
	cfg, cleanup := configFromSim()
	defer cleanup()

	// Create vSphere configuration object
	vs, err := newControllerNode(cfg)
	if err != nil {
		t.Fatalf("Failed to construct/authenticate vSphere: %s", err)
	}

	// Configure region and zone categories
	vs.cfg.Labels.Region = "k8s-region"
	vs.cfg.Labels.Zone = "k8s-zone"

	// Create vSphere client
	vsi, ok := vs.vsphereInstanceMap[cfg.Global.VCenterIP]
	if !ok {
		t.Fatalf("Couldn't get vSphere instance: %s", cfg.Global.VCenterIP)
	}

	err = vsi.conn.Connect(ctx)
	if err != nil {
		t.Errorf("Failed to connect to vSphere: %s", err)
	}

	// Lookup Datacenter for this test's Workspace
	dc, err := vclib.GetDatacenter(ctx, vsi.conn, vs.cfg.Workspace.Datacenter)
	if err != nil {
		t.Fatal(err)
	}

	// Property Collector instance
	pc := property.DefaultCollector(vsi.conn.Client)

	// find all hosts in VC
	finder := find.NewFinder(vsi.conn.Client, true)
	finder.SetDatacenter(dc.Datacenter)
	allVcHostsList, err := finder.HostSystemList(ctx, "*")
	if err != nil {
		t.Fatal(err)
	}
	var allVcHosts []vmwaretypes.ManagedObjectReference
	for _, h := range allVcHostsList {
		allVcHosts = append(allVcHosts, h.Reference())
	}

	// choose a cluster to apply zone/region tags
	cluster := simulator.Map.Any("ClusterComputeResource")
	var c mo.ClusterComputeResource
	if err := pc.RetrieveOne(ctx, cluster.Reference(), []string{"host"}, &c); err != nil {
		t.Fatal(err)
	}

	// choose one of the host inside this cluster to apply zone/region tags
	if c.Host == nil || len(c.Host) == 0 {
		t.Fatalf("This test needs a host inside a cluster.")
	}
	clusterHosts := c.Host
	sortHosts(clusterHosts)
	// pick the first host in the cluster to apply tags
	host := clusterHosts[0]
	remainingHostsInCluster := clusterHosts[1:]

	// Tag manager instance
	m := tags.NewManager(rest.NewClient(vsi.conn.Client))
	user := url.UserPassword(vsi.conn.Username, vsi.conn.Password)
	if err = m.Login(ctx, user); err != nil {
		t.Fatal(err)
	}

	// Create a region category
	regionCat, err := m.CreateCategory(ctx, &tags.Category{Name: vs.cfg.Labels.Region})
	if err != nil {
		t.Fatal(err)
	}

	// Create a region tag
	regionName := "k8s-region-US"
	regionTag, err := m.CreateTag(ctx, &tags.Tag{CategoryID: regionCat, Name: regionName})
	if err != nil {
		t.Fatal(err)
	}

	// Create a zone category
	zoneCat, err := m.CreateCategory(ctx, &tags.Category{Name: vs.cfg.Labels.Zone})
	if err != nil {
		t.Fatal(err)
	}

	// Create a zone tag
	zone1Name := "k8s-zone-US-CA1"
	zone1Tag, err := m.CreateTag(ctx, &tags.Tag{CategoryID: zoneCat, Name: zone1Name})
	if err != nil {
		t.Fatal(err)
	}
	zone1 := cloudprovider.Zone{FailureDomain: zone1Name, Region: regionName}

	// Create a second zone tag
	zone2Name := "k8s-zone-US-CA2"
	zone2Tag, err := m.CreateTag(ctx, &tags.Tag{CategoryID: zoneCat, Name: zone2Name})
	if err != nil {
		t.Fatal(err)
	}
	zone2 := cloudprovider.Zone{FailureDomain: zone2Name, Region: regionName}

	testcases := []struct {
		name        string
		tags        map[string][]mo.Reference
		zoneToHosts map[cloudprovider.Zone][]vmwaretypes.ManagedObjectReference
	}{
		{
			name:        "Zone and Region tags on host",
			tags:        map[string][]mo.Reference{zone1Tag: {host}, regionTag: {host}},
			zoneToHosts: map[cloudprovider.Zone][]vmwaretypes.ManagedObjectReference{zone1: {host}},
		},
		{
			name:        "Zone on host Region on datacenter",
			tags:        map[string][]mo.Reference{zone1Tag: {host}, regionTag: {dc}},
			zoneToHosts: map[cloudprovider.Zone][]vmwaretypes.ManagedObjectReference{zone1: {host}},
		},
		{
			name:        "Zone on cluster Region on datacenter",
			tags:        map[string][]mo.Reference{zone1Tag: {cluster}, regionTag: {dc}},
			zoneToHosts: map[cloudprovider.Zone][]vmwaretypes.ManagedObjectReference{zone1: clusterHosts},
		},
		{
			name:        "Zone on cluster and override on host",
			tags:        map[string][]mo.Reference{zone2Tag: {cluster}, zone1Tag: {host}, regionTag: {dc}},
			zoneToHosts: map[cloudprovider.Zone][]vmwaretypes.ManagedObjectReference{zone1: {host}, zone2: remainingHostsInCluster},
		},
		{
			name:        "Zone and Region on datacenter",
			tags:        map[string][]mo.Reference{zone1Tag: {dc}, regionTag: {dc}},
			zoneToHosts: map[cloudprovider.Zone][]vmwaretypes.ManagedObjectReference{zone1: allVcHosts},
		},
	}

	for _, testcase := range testcases {
		t.Run(testcase.name, func(t *testing.T) {
			// apply tags to datacenter/cluster/host as per this testcase
			for tagId, objects := range testcase.tags {
				for _, object := range objects {
					if err := m.AttachTag(ctx, tagId, object); err != nil {
						t.Fatal(err)
					}
				}
			}

			// run the test
			zoneToHosts, err := vs.GetZoneToHosts(ctx, vsi)
			if err != nil {
				t.Errorf("unexpected error