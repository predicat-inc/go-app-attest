package appattest

import (
	"crypto/ecdsa"
	"crypto/x509"
)

type Input struct {
	ServerChallenge []byte
	AttestationCBOR []byte
	KeyIdentifier   []byte

	OutAuthenticatorData *AuthenticatorData
}

type Output struct {
	Err               error
	AuthenticatorData *AuthenticatorData
	LeafCert          *x509.Certificate
}

// AttestedPubkey returns the key from the leaf certificate
func (o *Output) AttestedPubkey() ecdsa.PublicKey {
	return o.LeafCert.PublicKey.(ecdsa.PublicKey)
}

type Environment uint8

const (
	EnvironmentProd = iota
	EnvironmentDev
)

type Attestor interface {
	Attest(*Input) Output
}
