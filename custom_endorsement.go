/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package main

import (
	"errors"
	"fmt"

	"github.com/golang/protobuf/proto"
	endorsement "github.com/hyperledger/fabric/core/handlers/endorsement/api"
	identities "github.com/hyperledger/fabric/core/handlers/endorsement/api/identities"
	"github.com/hyperledger/fabric/protos/msp"
	"github.com/hyperledger/fabric/protos/peer"

	"./store"
)

// To build the plugin,
// run:
//    go build -buildmode=plugin -o escc.so plugin.go

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

	id := store.Save(identityBytes)

	//sEnc := b64.StdEncoding.EncodeToString(identityBytes)
	//ref, ok := certToRef[sEnc]
	//if !ok {
	//	fmt.Println(sEnc)
	//	panic("CERT REF NOT FOUND")
	//}
	//refBytes := []byte(ref)

	serializedIdentity := &msp.SerializedIdentity{Mspid: "", IdBytes: id}
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
