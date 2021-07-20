/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package main

import (
	b64 "encoding/base64"
	"fmt"
	"reflect"

	"github.com/golang/protobuf/proto"
	"github.com/hyperledger/fabric-protos-go/common"
	"github.com/hyperledger/fabric-protos-go/msp"
	commonerrors "github.com/hyperledger/fabric/common/errors"
	"github.com/hyperledger/fabric/common/flogging"
	"github.com/hyperledger/fabric/core/committer/txvalidator/v20/plugindispatcher"
	validation "github.com/hyperledger/fabric/core/handlers/validation/api"
	vc "github.com/hyperledger/fabric/core/handlers/validation/api/capabilities"
	vi "github.com/hyperledger/fabric/core/handlers/validation/api/identities"
	vp "github.com/hyperledger/fabric/core/handlers/validation/api/policies"
	vs "github.com/hyperledger/fabric/core/handlers/validation/api/state"
	v12 "github.com/hyperledger/fabric/core/handlers/validation/builtin/v12"
	v13 "github.com/hyperledger/fabric/core/handlers/validation/builtin/v13"
	v20 "github.com/hyperledger/fabric/core/handlers/validation/builtin/v20"
	"github.com/hyperledger/fabric/protoutil"
	"github.com/pkg/errors"
)

// refs
const (
	ref__peer0_rzd_rails_rzd = "ref://peer0.rzd.rails.rzd-cert.pem"
	ref__peer0_hmk_rails_rzd = "ref://peer0.hmk.rails.rzd-cert.pem"
	ref__peer0_evrazzsmk_rails_rzd = "ref://peer0.evrazzsmk.rails.rzd-cert.pem"
)

// certs
const (
	pem__peer0_rzd_rails_rzd = "CgZSWkRNU1ASigYtLS0tLUJFR0lOIENFUlRJRklDQVRFLS0tLS0KTUlJQ0VUQ0NBYmVnQXdJQkFnSVJBTlozb05NNHFrRzV2WE5WdWtsT0Ruc3dDZ1lJS29aSXpqMEVBd0l3YlRFTApNQWtHQTFVRUJoTUNWVk14RXpBUkJnTlZCQWdUQ2tOaGJHbG1iM0p1YVdFeEZqQVVCZ05WQkFjVERWTmhiaUJHCmNtRnVZMmx6WTI4eEZqQVVCZ05WQkFvVERYSjZaQzV5WVdsc2N5NXllbVF4R1RBWEJnTlZCQU1URUdOaExuSjYKWkM1eVlXbHNjeTV5ZW1Rd0hoY05NakV3TnpFME1EZ3hOekF3V2hjTk16RXdOekV5TURneE56QXdXakJZTVFzdwpDUVlEVlFRR0V3SlZVekVUTUJFR0ExVUVDQk1LUTJGc2FXWnZjbTVwWVRFV01CUUdBMVVFQnhNTlUyRnVJRVp5CllXNWphWE5qYnpFY01Cb0dBMVVFQXhNVGNHVmxjakF1Y25wa0xuSmhhV3h6TG5KNlpEQlpNQk1HQnlxR1NNNDkKQWdFR0NDcUdTTTQ5QXdFSEEwSUFCTFluTUo5N2t4L0cxOENLUGhRMUpmSWFNenpBaEUrWXhGbmFuMTRSVFRxQgpxby9LaXpjSlJZTjVxOVNkK0sxNnVQUG56VFF2K0VxeVk5YWErM2J4RHhPalRUQkxNQTRHQTFVZER3RUIvd1FFCkF3SUhnREFNQmdOVkhSTUJBZjhFQWpBQU1Dc0dBMVVkSXdRa01DS0FJQnh0YTNycFZCcVhpbmpsQ0EyWFowZ1cKRDNTREp5dGgwak5Dbi9HODd0eEpNQW9HQ0NxR1NNNDlCQU1DQTBnQU1FVUNJUUNBVUUyUmRsckpsWWR6S20xLwpnYm5jMklob0wvUXluU0paWHl1T1JtZXRPZ0lnQitYWnNIZ1lSUlBFeXJvczFocnY3dDhsVDdtUWIyaWlPeDJoClBJQTNCS1U9Ci0tLS0tRU5EIENFUlRJRklDQVRFLS0tLS0K"
	pem__peer0_hmk_rails_rzd = "CgZITUtNU1AShgYtLS0tLUJFR0lOIENFUlRJRklDQVRFLS0tLS0KTUlJQ0R6Q0NBYmFnQXdJQkFnSVFSMVh4K2NTaEJ2YXZLSlRUMnZyTXRqQUtCZ2dxaGtqT1BRUURBakJ0TVFzdwpDUVlEVlFRR0V3SlZVekVUTUJFR0ExVUVDQk1LUTJGc2FXWnZjbTVwWVRFV01CUUdBMVVFQnhNTlUyRnVJRVp5CllXNWphWE5qYnpFV01CUUdBMVVFQ2hNTmFHMXJMbkpoYVd4ekxuSjZaREVaTUJjR0ExVUVBeE1RWTJFdWFHMXIKTG5KaGFXeHpMbko2WkRBZUZ3MHlNVEEzTVRRd09ERTNNREJhRncwek1UQTNNVEl3T0RFM01EQmFNRmd4Q3pBSgpCZ05WQkFZVEFsVlRNUk13RVFZRFZRUUlFd3BEWVd4cFptOXlibWxoTVJZd0ZBWURWUVFIRXcxVFlXNGdSbkpoCmJtTnBjMk52TVJ3d0dnWURWUVFERXhOd1pXVnlNQzVvYldzdWNtRnBiSE11Y25wa01Ga3dFd1lIS29aSXpqMEMKQVFZSUtvWkl6ajBEQVFjRFFnQUVyUm0zQm53REpCYzB0bk1PZ2F4OTd1ZWY1MjFDRnpHbFcxSG5ZNTdlclpzZAp3LzJpSExBdmkvb0pLNHRZUS9pd2hYTjBEMTZ5Z0g3eWEySkhqYTVjTGFOTk1Fc3dEZ1lEVlIwUEFRSC9CQVFECkFnZUFNQXdHQTFVZEV3RUIvd1FDTUFBd0t3WURWUjBqQkNRd0lvQWdRUVdOVUx5RTdDNTFOTVRJTGVPL1h6WkoKL2pzTllnMld1UjB5MERKV1loOHdDZ1lJS29aSXpqMEVBd0lEUndBd1JBSWdZL00wYmpSZ1JqaHFWSTJGeXB5cwpBSHNwYnI3T3cvS1lQckhNT3BaUlEyc0NJRldySW9NTGNuTDdoQk1oWDRHczdKdEU2RjZFcmtwbmp2ME16UHRKCmxuYksKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo="
	pem__peer0_evrazzsmk_rails_rzd = "CgxFVlJBWlpTTUtNU1ASngYtLS0tLUJFR0lOIENFUlRJRklDQVRFLS0tLS0KTUlJQ0lUQ0NBY2lnQXdJQkFnSVFNNTlCbWNOeHVmNjZ3QldPUHhWY3pEQUtCZ2dxaGtqT1BRUURBakI1TVFzdwpDUVlEVlFRR0V3SlZVekVUTUJFR0ExVUVDQk1LUTJGc2FXWnZjbTVwWVRFV01CUUdBMVVFQnhNTlUyRnVJRVp5CllXNWphWE5qYnpFY01Cb0dBMVVFQ2hNVFpYWnlZWHA2YzIxckxuSmhhV3h6TG5KNlpERWZNQjBHQTFVRUF4TVcKWTJFdVpYWnlZWHA2YzIxckxuSmhhV3h6TG5KNlpEQWVGdzB5TVRBM01UUXdPREUzTURCYUZ3MHpNVEEzTVRJdwpPREUzTURCYU1GNHhDekFKQmdOVkJBWVRBbFZUTVJNd0VRWURWUVFJRXdwRFlXeHBabTl5Ym1saE1SWXdGQVlEClZRUUhFdzFUWVc0Z1JuSmhibU5wYzJOdk1TSXdJQVlEVlFRREV4bHdaV1Z5TUM1bGRuSmhlbnB6YldzdWNtRnAKYkhNdWNucGtNRmt3RXdZSEtvWkl6ajBDQVFZSUtvWkl6ajBEQVFjRFFnQUVGZ0Q5cnZCd3VNREtCcFRDUmNYRwpFMUpXUG5FRVV5R3NIQ3RBb245RXQ5aGNRd1hLUnNLVytsdmsxMFRkT2FFT3h6d0tDa09ISHJneXQ2MkliNlRWCmhhTk5NRXN3RGdZRFZSMFBBUUgvQkFRREFnZUFNQXdHQTFVZEV3RUIvd1FDTUFBd0t3WURWUjBqQkNRd0lvQWcKZDVIYS9TdVpvcnhDYWR4SjdNVC81MnFkWFkremhubzE1OC9YcUNoVFAyNHdDZ1lJS29aSXpqMEVBd0lEUndBdwpSQUlnREU5TXU1SDFQby9USW5nUFZyeHFzMVVzWlRrRERtZzhEdkczTjlXR1g3NENJRytpdnNvdFFCOGVqUm9HCmwxVHRjSGJKNG1UY1FMRjF3UGFUdjFKR0NYSk8KLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo="
)

// ref to cert map
var refToCert = map[string]string{
	ref__peer0_rzd_rails_rzd: pem__peer0_rzd_rails_rzd,
	ref__peer0_hmk_rails_rzd: pem__peer0_hmk_rails_rzd,
	ref__peer0_evrazzsmk_rails_rzd: pem__peer0_evrazzsmk_rails_rzd,
}

var logger = flogging.MustGetLogger("vscc")

type DefaultValidationFactory struct{}

func (*DefaultValidationFactory) New() validation.Plugin {
	return &DefaultValidation{}
}

type DefaultValidation struct {
	Capabilities    vc.Capabilities
	TxValidatorV1_2 TransactionValidator
	TxValidatorV1_3 TransactionValidator
	TxValidatorV2_0 TransactionValidator
}

//go:generate mockery -dir . -name TransactionValidator -case underscore -output mocks/
type TransactionValidator interface {
	Validate(block *common.Block, namespace string, txPosition int, actionPosition int, policy []byte) commonerrors.TxValidationError
}

func (v *DefaultValidation) Validate(block *common.Block, namespace string, txPosition int, actionPosition int, contextData ...validation.ContextDatum) error {
	if len(contextData) == 0 {
		logger.Panicf("Expected to receive policy bytes in context data")
	}

	serializedPolicy, isSerializedPolicy := contextData[0].(vp.SerializedPolicy)
	if !isSerializedPolicy {
		logger.Panicf("Expected to receive a serialized policy in the first context data")
	}
	if block == nil || block.Data == nil {
		return errors.New("empty block")
	}
	if txPosition >= len(block.Data.Data) {
		return errors.Errorf("block has only %d transactions, but requested tx at position %d", len(block.Data.Data), txPosition)
	}
	if block.Header == nil {
		return errors.Errorf("no block header")
	}

	var err error

	switch {
	case v.Capabilities.V2_0Validation():
		err = v.TxValidatorV2_0.Validate(block, namespace, txPosition, actionPosition, serializedPolicy.Bytes())

	case v.Capabilities.V1_3Validation():
		err = v.TxValidatorV1_3.Validate(block, namespace, txPosition, actionPosition, serializedPolicy.Bytes())

	case v.Capabilities.V1_2Validation():
		fallthrough

	default:
		err = v.TxValidatorV1_2.Validate(block, namespace, txPosition, actionPosition, serializedPolicy.Bytes())
	}

	logger.Debugf("block %d, namespace: %s, tx %d validation results is: %v", block.Header.Number, namespace, txPosition, err)
	return convertErrorTypeOrPanic(err)
}

func convertErrorTypeOrPanic(err error) error {
	if err == nil {
		return nil
	}
	if err, isExecutionError := err.(*commonerrors.VSCCExecutionFailureError); isExecutionError {
		return &validation.ExecutionFailureError{
			Reason: err.Error(),
		}
	}
	if err, isEndorsementError := err.(*commonerrors.VSCCEndorsementPolicyError); isEndorsementError {
		return err
	}
	logger.Panicf("Programming error: The error is %v, of type %v but expected to be either ExecutionFailureError or VSCCEndorsementPolicyError", err, reflect.TypeOf(err))
	return &validation.ExecutionFailureError{Reason: fmt.Sprintf("error of type %v returned from VSCC", reflect.TypeOf(err))}
}

type CustomPolicyEvaluator struct {
	original  vp.PolicyEvaluator
}

func setDataIdentity(data *protoutil.SignedData, identity []byte) []byte {
	prespBytes := data.Data[:len(data.Data) - len(data.Identity)]
	newData := make([]byte, len(prespBytes)+len(identity))
	copy(newData, prespBytes)
	copy(newData[len(prespBytes):], identity)
	return newData
}

// Evaluate takes a set of SignedData and evaluates whether this set of signatures satisfies the policy
func (pe *CustomPolicyEvaluator) Evaluate(policyBytes []byte, signatureSet []*protoutil.SignedData) error {
	serializedIdentity := &msp.SerializedIdentity{}
	err := proto.Unmarshal(signatureSet[0].Identity, serializedIdentity)
	if err != nil {
		panic(err)
	}

	sigSet := signatureSet
	ref := string(serializedIdentity.IdBytes)
	if pem, ok := refToCert[ref]; ok {
		sDec, _ := b64.StdEncoding.DecodeString(pem)
		data := setDataIdentity(signatureSet[0], sDec)

		sigSet[0].Data = data
		sigSet[0].Identity = sDec
		sigSet[0].Signature = signatureSet[0].Signature
	}

	return pe.original.Evaluate(policyBytes, sigSet)
}

func (v *DefaultValidation) Init(dependencies ...validation.Dependency) error {
	var (
		d   vi.IdentityDeserializer
		c   vc.Capabilities
		sf  vs.StateFetcher
		pe  vp.PolicyEvaluator
		cor plugindispatcher.CollectionResources
	)
	for _, dep := range dependencies {
		if deserializer, isIdentityDeserializer := dep.(vi.IdentityDeserializer); isIdentityDeserializer {
			d = deserializer
		}

		if capabilities, isCapabilities := dep.(vc.Capabilities); isCapabilities {
			c = capabilities
		}
		if stateFetcher, isStateFetcher := dep.(vs.StateFetcher); isStateFetcher {
			sf = stateFetcher
		}
		if policyEvaluator, isPolicyFetcher := dep.(vp.PolicyEvaluator); isPolicyFetcher {
			pe = policyEvaluator
			pe = &CustomPolicyEvaluator{pe}
		}

		if collectionResources, isCollectionResources := dep.(plugindispatcher.CollectionResources); isCollectionResources {
			cor = collectionResources
		}
	}
	if sf == nil {
		return errors.New("stateFetcher not passed in init")
	}
	if d == nil {
		return errors.New("identityDeserializer not passed in init")
	}
	if c == nil {
		return errors.New("capabilities not passed in init")
	}
	if pe == nil {
		return errors.New("policy fetcher not passed in init")
	}
	if cor == nil {
		return errors.New("collection resources not passed in init")
	}

	v.Capabilities = c
	v.TxValidatorV1_2 = v12.New(c, sf, d, pe)
	v.TxValidatorV1_3 = v13.New(c, sf, d, pe)
	v.TxValidatorV2_0 = v20.New(c, sf, d, pe, cor)

	return nil
}

func NewPluginFactory() validation.PluginFactory {
	return &DefaultValidationFactory{}
}
