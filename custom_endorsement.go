/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package main

import (
	b64 "encoding/base64"
	"errors"
	"fmt"

	"github.com/golang/protobuf/proto"
	endorsement "github.com/hyperledger/fabric/core/handlers/endorsement/api"
	identities "github.com/hyperledger/fabric/core/handlers/endorsement/api/identities"
	"github.com/hyperledger/fabric/protos/msp"
	"github.com/hyperledger/fabric/protos/peer"
)

// To build the plugin,
// run:
//    go build -buildmode=plugin -o escc.so plugin.go

// refs
const (
	ref__peer0_rzd_rails_rzd = "ref://peer0.rzd.rails.rzd-cert.pem"
	ref__peer0_hmk_rails_rzd = "ref://peer0.hmk.rails.rzd-cert.pem"
	ref__peer0_evrazzsmk_rails_rzd = "ref://peer0.evrazzsmk.rails.rzd-cert.pem"
)

// certs
// from path /var/hyperledger/certs/peerOrganizations/org.rails.rzd/peers/peer0.org.rails.rzd/msp/signcerts
const (
	pem__peer0_rzd_rails_rzd = "CgZSWkRNU1ASigYtLS0tLUJFR0lOIENFUlRJRklDQVRFLS0tLS0KTUlJQ0VUQ0NBYmVnQXdJQkFnSVJBTlozb05NNHFrRzV2WE5WdWtsT0Ruc3dDZ1lJS29aSXpqMEVBd0l3YlRFTApNQWtHQTFVRUJoTUNWVk14RXpBUkJnTlZCQWdUQ2tOaGJHbG1iM0p1YVdFeEZqQVVCZ05WQkFjVERWTmhiaUJHCmNtRnVZMmx6WTI4eEZqQVVCZ05WQkFvVERYSjZaQzV5WVdsc2N5NXllbVF4R1RBWEJnTlZCQU1URUdOaExuSjYKWkM1eVlXbHNjeTV5ZW1Rd0hoY05NakV3TnpFME1EZ3hOekF3V2hjTk16RXdOekV5TURneE56QXdXakJZTVFzdwpDUVlEVlFRR0V3SlZVekVUTUJFR0ExVUVDQk1LUTJGc2FXWnZjbTVwWVRFV01CUUdBMVVFQnhNTlUyRnVJRVp5CllXNWphWE5qYnpFY01Cb0dBMVVFQXhNVGNHVmxjakF1Y25wa0xuSmhhV3h6TG5KNlpEQlpNQk1HQnlxR1NNNDkKQWdFR0NDcUdTTTQ5QXdFSEEwSUFCTFluTUo5N2t4L0cxOENLUGhRMUpmSWFNenpBaEUrWXhGbmFuMTRSVFRxQgpxby9LaXpjSlJZTjVxOVNkK0sxNnVQUG56VFF2K0VxeVk5YWErM2J4RHhPalRUQkxNQTRHQTFVZER3RUIvd1FFCkF3SUhnREFNQmdOVkhSTUJBZjhFQWpBQU1Dc0dBMVVkSXdRa01DS0FJQnh0YTNycFZCcVhpbmpsQ0EyWFowZ1cKRDNTREp5dGgwak5Dbi9HODd0eEpNQW9HQ0NxR1NNNDlCQU1DQTBnQU1FVUNJUUNBVUUyUmRsckpsWWR6S20xLwpnYm5jMklob0wvUXluU0paWHl1T1JtZXRPZ0lnQitYWnNIZ1lSUlBFeXJvczFocnY3dDhsVDdtUWIyaWlPeDJoClBJQTNCS1U9Ci0tLS0tRU5EIENFUlRJRklDQVRFLS0tLS0K"
	pem__peer0_hmk_rails_rzd = "CgZITUtNU1AShgYtLS0tLUJFR0lOIENFUlRJRklDQVRFLS0tLS0KTUlJQ0R6Q0NBYmFnQXdJQkFnSVFSMVh4K2NTaEJ2YXZLSlRUMnZyTXRqQUtCZ2dxaGtqT1BRUURBakJ0TVFzdwpDUVlEVlFRR0V3SlZVekVUTUJFR0ExVUVDQk1LUTJGc2FXWnZjbTVwWVRFV01CUUdBMVVFQnhNTlUyRnVJRVp5CllXNWphWE5qYnpFV01CUUdBMVVFQ2hNTmFHMXJMbkpoYVd4ekxuSjZaREVaTUJjR0ExVUVBeE1RWTJFdWFHMXIKTG5KaGFXeHpMbko2WkRBZUZ3MHlNVEEzTVRRd09ERTNNREJhRncwek1UQTNNVEl3T0RFM01EQmFNRmd4Q3pBSgpCZ05WQkFZVEFsVlRNUk13RVFZRFZRUUlFd3BEWVd4cFptOXlibWxoTVJZd0ZBWURWUVFIRXcxVFlXNGdSbkpoCmJtTnBjMk52TVJ3d0dnWURWUVFERXhOd1pXVnlNQzVvYldzdWNtRnBiSE11Y25wa01Ga3dFd1lIS29aSXpqMEMKQVFZSUtvWkl6ajBEQVFjRFFnQUVyUm0zQm53REpCYzB0bk1PZ2F4OTd1ZWY1MjFDRnpHbFcxSG5ZNTdlclpzZAp3LzJpSExBdmkvb0pLNHRZUS9pd2hYTjBEMTZ5Z0g3eWEySkhqYTVjTGFOTk1Fc3dEZ1lEVlIwUEFRSC9CQVFECkFnZUFNQXdHQTFVZEV3RUIvd1FDTUFBd0t3WURWUjBqQkNRd0lvQWdRUVdOVUx5RTdDNTFOTVRJTGVPL1h6WkoKL2pzTllnMld1UjB5MERKV1loOHdDZ1lJS29aSXpqMEVBd0lEUndBd1JBSWdZL00wYmpSZ1JqaHFWSTJGeXB5cwpBSHNwYnI3T3cvS1lQckhNT3BaUlEyc0NJRldySW9NTGNuTDdoQk1oWDRHczdKdEU2RjZFcmtwbmp2ME16UHRKCmxuYksKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo="
	pem__peer0_evrazzsmk_rails_rzd = "CgxFVlJBWlpTTUtNU1ASngYtLS0tLUJFR0lOIENFUlRJRklDQVRFLS0tLS0KTUlJQ0lUQ0NBY2lnQXdJQkFnSVFNNTlCbWNOeHVmNjZ3QldPUHhWY3pEQUtCZ2dxaGtqT1BRUURBakI1TVFzdwpDUVlEVlFRR0V3SlZVekVUTUJFR0ExVUVDQk1LUTJGc2FXWnZjbTVwWVRFV01CUUdBMVVFQnhNTlUyRnVJRVp5CllXNWphWE5qYnpFY01Cb0dBMVVFQ2hNVFpYWnlZWHA2YzIxckxuSmhhV3h6TG5KNlpERWZNQjBHQTFVRUF4TVcKWTJFdVpYWnlZWHA2YzIxckxuSmhhV3h6TG5KNlpEQWVGdzB5TVRBM01UUXdPREUzTURCYUZ3MHpNVEEzTVRJdwpPREUzTURCYU1GNHhDekFKQmdOVkJBWVRBbFZUTVJNd0VRWURWUVFJRXdwRFlXeHBabTl5Ym1saE1SWXdGQVlEClZRUUhFdzFUWVc0Z1JuSmhibU5wYzJOdk1TSXdJQVlEVlFRREV4bHdaV1Z5TUM1bGRuSmhlbnB6YldzdWNtRnAKYkhNdWNucGtNRmt3RXdZSEtvWkl6ajBDQVFZSUtvWkl6ajBEQVFjRFFnQUVGZ0Q5cnZCd3VNREtCcFRDUmNYRwpFMUpXUG5FRVV5R3NIQ3RBb245RXQ5aGNRd1hLUnNLVytsdmsxMFRkT2FFT3h6d0tDa09ISHJneXQ2MkliNlRWCmhhTk5NRXN3RGdZRFZSMFBBUUgvQkFRREFnZUFNQXdHQTFVZEV3RUIvd1FDTUFBd0t3WURWUjBqQkNRd0lvQWcKZDVIYS9TdVpvcnhDYWR4SjdNVC81MnFkWFkremhubzE1OC9YcUNoVFAyNHdDZ1lJS29aSXpqMEVBd0lEUndBdwpSQUlnREU5TXU1SDFQby9USW5nUFZyeHFzMVVzWlRrRERtZzhEdkczTjlXR1g3NENJRytpdnNvdFFCOGVqUm9HCmwxVHRjSGJKNG1UY1FMRjF3UGFUdjFKR0NYSk8KLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo="
)

// cert to ref map
var certToRef = map[string]string{
	pem__peer0_rzd_rails_rzd:       ref__peer0_rzd_rails_rzd,
	pem__peer0_hmk_rails_rzd:       ref__peer0_hmk_rails_rzd,
	pem__peer0_evrazzsmk_rails_rzd: ref__peer0_evrazzsmk_rails_rzd,
}

// CustomEndorsementFactory returns an endorsement plugin factory which returns plugins
// that behave as the Custom endorsement system chaincode
type CustomEndorsementFactory struct{}

// New returns an endorsement plugin that behaves as the Custom endorsement system chaincode
func (*CustomEndorsementFactory) New() endorsement.Plugin {
	return &CustomEndorsement{}
}

// CustomEndorsement is an endorsement plugin that behaves as the Custom endorsement system chaincode
type CustomEndorsement struct {
	identities.SigningIdentityFetcher
}

// Endorse signs the given payload(ProposalResponsePayload bytes), and optionally mutates it.
// Returns:
// The Endorsement: A signature over the payload, and an identity that is used to verify the signature
// The payload that was given as input (could be modified within this function)
// Or error on failure
func (e *CustomEndorsement) Endorse(prpBytes []byte, sp *peer.SignedProposal) (*peer.Endorsement, []byte, error) {
	signer, err := e.SigningIdentityForRequest(sp)
	if err != nil {
		return nil, nil, fmt.Errorf("failed fetching signing identity: %v", err)
	}
	// serialize the signing identity
	identityBytes, err := signer.Serialize()
	if err != nil {
		return nil, nil, fmt.Errorf("could not serialize the signing identity: %v", err)
	}

	sEnc := b64.StdEncoding.EncodeToString(identityBytes)
	ref, ok := certToRef[sEnc]
	if !ok {
		fmt.Println(sEnc)
		panic("CERT REF NOT FOUND")
	}

	refBytes := []byte(ref)
	serializedIdentity := &msp.SerializedIdentity{Mspid: "RZDMSP", IdBytes: refBytes}
	serializedIdentityBytes, err := proto.Marshal(serializedIdentity)
	if err != nil {
		panic(err)
	}

	// sign the concatenation of the proposal response and the serialized endorser identity with this endorser's key
	signature, err := signer.Sign(append(prpBytes, identityBytes...))
	if err != nil {
		return nil, nil, fmt.Errorf("could not sign the proposal response payload: %v", err)
	}

	endorsement := &peer.Endorsement{Signature: signature, Endorser: serializedIdentityBytes}
	return endorsement, prpBytes, nil
}

// Init injects dependencies into the instance of the Plugin
func (e *CustomEndorsement) Init(dependencies ...endorsement.Dependency) error {
	for _, dep := range dependencies {
		sIDFetcher, isSigningIdentityFetcher := dep.(identities.SigningIdentityFetcher)
		if !isSigningIdentityFetcher {
			continue
		}
		e.SigningIdentityFetcher = sIDFetcher
		return nil
	}
	return errors.New("could not find SigningIdentityFetcher in dependencies")
}

// NewPluginFactory is the function ran by the plugin infrastructure to create an endorsement plugin factory.
func NewPluginFactory() endorsement.PluginFactory {
	return &CustomEndorsementFactory{}
}
