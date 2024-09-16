package mint

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"time"

	"github.com/fxamacker/cbor/v2"
	appattest "github.com/predicat-inc/go-app-attest"
)

// This package provides an API for minting attestation documents.

type Input struct {
	IntermediatesDER  [][]byte
	IssuerCertificate *x509.Certificate
	IssuerKey         *ecdsa.PrivateKey
	AttestedKey       *ecdsa.PublicKey
	AAGUID            []byte

	NotBefore time.Time
	NotAfter  time.Time

	ServerChallenge []byte
	BundleIDHash    []byte

	// MutateLeaf provides the caller with an opportunity to modify the certificate template before
	// it is processed.
	MutateLeafTemplate func(*x509.Certificate)
}

type Output struct {
	Err         error
	Attestation []byte
}

func Mint(input *Input) Output {

	// compute the key hash
	keyIdentifier := appattest.ComputeKeyHash(input.AttestedKey)

	// build and marshal the authenticator data
	ad := appattest.AuthenticatorData{
		RelayingPartyHash: input.BundleIDHash,
		SignCount:         3,
		Flags:             appattest.ADF_HAS_ATTESTED_CREDENTIAL_DATA,
		AttestedCredentialData: appattest.AttestedCredentialData{
			AAGUID:       input.AAGUID,
			CredentialID: keyIdentifier[:],
		},
	}

	adb, err := MarhsalAuthenticatorData(&ad)
	if err != nil {
		return Output{Err: err}
	}

	// compute rawnonce which will be put in an ASN.1 container
	rawnonce, err := appattest.ComputeNonce(adb, input.ServerChallenge)
	if err != nil {
		return Output{Err: err}
	}

	// nonce is an asn.1 container containing the computed nonce
	nonce, err := asn1.Marshal(appattest.ASN1AANonceContainer{Nonce: rawnonce[:]})
	if err != nil {
		return Output{Err: err}
	}

	// mint the leaf certificate
	exts := []pkix.Extension{
		{
			Id:    appattest.NonceOID,
			Value: nonce,
		},
	}

	leafder, err := generateLeafCert(input.AttestedKey,
		"mock leaf",
		input.IssuerCertificate,
		input.IssuerKey,
		exts,
		input.NotBefore,
		input.NotAfter,
		input.MutateLeafTemplate,
	)
	if err != nil {
		return Output{Err: err}
	}

	x5c := make([][]byte, 1+len(input.IntermediatesDER))
	x5c[0] = leafder
	_ = copy(x5c[1:], input.IntermediatesDER)

	// build the attestation statement
	as := appattest.AttestationStatement{
		X509CertChain: x5c,
		Receipt:       nil, // do not provide a receipt yet as the server part is not mocked
	}

	// build and marshal the attestation object
	ao := &appattest.AttestationObject{
		AttestationStatement: as,
		AuthData:             adb,
		Format:               appattest.Format,
	}

	// marshal the attestation object
	aob, err := cbor.Marshal(ao)
	if err != nil {
		return Output{Err: err}
	}

	return Output{
		Attestation: aob,
	}
}

func generateLeafCert(
	pubkey *ecdsa.PublicKey,
	commonName string,
	parentCert *x509.Certificate,
	parentKey *ecdsa.PrivateKey,
	exts []pkix.Extension,
	notBefore time.Time,
	notAfter time.Time,
	mutateLeaf func(cert *x509.Certificate),
) ([]byte, error) {
	template := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: commonName},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		ExtraExtensions:       exts,
	}

	if mutateLeaf != nil {
		mutateLeaf(&template)
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, parentCert, pubkey, parentKey)
	if err != nil {
		return nil, err
	}
	return certDER, nil
}
