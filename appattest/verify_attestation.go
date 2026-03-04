package appattest

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"fmt"
	"reflect"
	"slices"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/pkg/errors"
	"github.com/splitsecure/go-app-attest/authenticatordata"
)

const (
	Format = "apple-appattest"
)

var (
	NonceOID   = asn1.ObjectIdentifier{1, 2, 840, 113635, 100, 8, 2}
	AAGUIDProd = Environment("appattest\x00\x00\x00\x00\x00\x00\x00")
	AAGUIDDev  = Environment("appattestdevelop")
)

type Environment = []byte

type VerifyAttestationInputPure struct {
	AttestationInput *VerifyAttestationInput
	Time             time.Time
	AARoots          []*x509.Certificate
}

type VerifyAttestationOutput struct {
	AuthenticatorData *authenticatordata.T
	LeafCert          *x509.Certificate

	EnvironmentGUID Environment
	BundleDigest    []byte
	KeyID           []byte

	// DeviceInfo contains device and OS metadata extracted from the leaf
	// certificate. Nil if the extension is absent or unparseable.
	DeviceInfo *DeviceInfo
}

// AttestedPubkey returns the key from the leaf certificate
func (o *VerifyAttestationOutput) AttestedPubkey() *ecdsa.PublicKey {
	return o.LeafCert.PublicKey.(*ecdsa.PublicKey)
}

// VerifyAttestationPure performs attestation without the guardrails provided by AppAttestImpl.
func VerifyAttestationPure(in *VerifyAttestationInputPure) (VerifyAttestationOutput, error) {
	// unmarshal the attestation object
	attestObj := AttestationObject{}
	err := cbor.Unmarshal(in.AttestationInput.AttestationCBOR, &attestObj)
	if err != nil {
		return VerifyAttestationOutput{}, fmt.Errorf("unmarshalling attestation object: %w", err)
	}

	// ensure format is correct
	if attestObj.Format != Format {
		return VerifyAttestationOutput{}, fmt.Errorf("attestation object format mismatch: expected '%s', got '%s'", Format, attestObj.Format)
	}

	// Parse certificate chain from bytes to certificates
	chain := make([]*x509.Certificate, len(attestObj.AttestationStatement.X509CertChain))
	for i, certBytes := range attestObj.AttestationStatement.X509CertChain {
		cert, err := x509.ParseCertificate(certBytes)
		if err != nil {
			return VerifyAttestationOutput{}, fmt.Errorf("parsing certificate at index %d: %w", i, err)
		}
		chain[i] = cert
	}

	if err := VerifyChain(chain, in.AARoots); err != nil {
		return VerifyAttestationOutput{}, fmt.Errorf("verifying certificate chain: %w", err)
	}

	// get the leaf certificate (first in chain)
	leafCert := chain[0]

	// > 2. Create clientDataHash as the SHA256 hash of the one-time challenge your server sends
	// > to your app before performing the attestation,
	// > and append that hash to the end of the authenticator data (authData from the decoded object).
	// > 3. Generate a new SHA256 hash of the composite item to create nonce.

	// clientDataHash := sha256.Sum256(in.AttestationInput.ServerChallenge)
	clientDataHash := in.AttestationInput.ServerChallenge

	nonce, err := ComputeNonce(attestObj.AuthData, clientDataHash[:])
	if err != nil {
		return VerifyAttestationOutput{}, fmt.Errorf("computing nonce: %w", err)
	}

	nonceFromCert, err := extractNonceFromCert(leafCert)
	if err != nil {
		return VerifyAttestationOutput{}, fmt.Errorf("extracting nonce from leaf certificate: %w", err)
	}

	if !bytes.Equal(nonceFromCert, nonce[:]) {
		return VerifyAttestationOutput{}, fmt.Errorf("nonce from cert did not match computed nonce: %s != %s", hex.EncodeToString(nonceFromCert), hex.EncodeToString(nonce[:]))
	}

	certPubKey, ok := leafCert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return VerifyAttestationOutput{}, fmt.Errorf("downcasting pubkey: unexpected type '%s'", reflect.TypeOf(leafCert.PublicKey))
	}

	computedPubkeyHash := ComputeKeyHash(certPubKey)

	authenticatorData := in.AttestationInput.OutAuthenticatorData
	if authenticatorData == nil {
		authenticatorData = &authenticatordata.T{}
	}

	if err = authenticatordata.Unmarshal(attestObj.AuthData, authenticatorData); err != nil {
		return VerifyAttestationOutput{}, errors.Wrap(err, "unmarshalling authenticator data")
	}

	// > 9. Verify that the authenticator data’s credentialId field is the same as the key identifier.
	if !bytes.Equal(computedPubkeyHash[:], authenticatorData.AttestedCredentialData.CredentialID) {
		return VerifyAttestationOutput{}, fmt.Errorf("key identifier did not match attested credential id of authenticator data")
	}

	return VerifyAttestationOutput{
		AuthenticatorData: authenticatorData,
		LeafCert:          leafCert,

		EnvironmentGUID: authenticatorData.AttestedCredentialData.AAGUID,
		BundleDigest:    authenticatorData.RelayingPartyHash,
		KeyID:           computedPubkeyHash[:],

		DeviceInfo: parseDeviceInfo(leafCert),
	}, nil
}

func extractNonceFromCert(c *x509.Certificate) ([]byte, error) {
	var oidValue []byte
	for _, ext := range c.Extensions {
		if slices.Equal(NonceOID, ext.Id) {
			oidValue = ext.Value
			break
		}
	}

	if oidValue == nil {
		return nil, errors.New("could not find nonce oid")
	}

	nc := ASN1AANonceContainer{}
	if _, err := asn1.Unmarshal(oidValue, &nc); err != nil {
		return nil, err
	}

	return nc.Nonce, nil
}

type AttestationObject struct {
	Format               string               `cbor:"fmt"`
	AttestationStatement AttestationStatement `cbor:"attStmt"`
	AuthData             []byte               `cbor:"authData"` // https://www.w3.org/TR/webauthn/#sctn-authenticator-data
}

type AttestationStatement struct {
	X509CertChain [][]byte `cbor:"x5c"` // leaf cert is first
	Receipt       []byte   `cbor:"receipt"`
}

type ASN1AANonceContainer struct {
	Nonce []byte `asn1:"tag:1,explicit"`
}

func ellipticPointToX962Uncompressed(pub *ecdsa.PublicKey) []byte {
	// X9.62 uncompressed point format: 0x04 || X || Y
	x962Bytes := make([]byte, 65)
	x962Bytes[0] = 0x04 // Uncompressed point indicator
	xBytes := pub.X.Bytes()
	yBytes := pub.Y.Bytes()
	copy(x962Bytes[1+32-len(xBytes):33], xBytes) // Pad X to 32 bytes
	copy(x962Bytes[33+32-len(yBytes):], yBytes)  // Pad Y to 32 bytes
	return x962Bytes
}

func ComputeNonce(authData, clientDataHash []byte) (res [sha256.Size]byte, err error) {
	nonceDigest := sha256.New()
	if _, err = nonceDigest.Write(authData); err != nil {
		err = errors.Wrap(err, "writing auth data to digest")
		return
	}

	if _, err = nonceDigest.Write(clientDataHash); err != nil {
		err = errors.Wrap(err, "writing challenge checksum to digest")
		return
	}

	nonceDigest.Sum(res[:0])
	return
}

func ComputeKeyHash(key *ecdsa.PublicKey) [sha256.Size]byte {
	return sha256.Sum256(ellipticPointToX962Uncompressed(key))
}
