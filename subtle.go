package appattest

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"fmt"
	"reflect"
	"slices"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/pkg/errors"
)

const (
	Format = "apple-appattest"
)

type SubtleAttestInput struct {
	AttestationInput *Input
	Time             time.Time
	BundleIDHash     []byte

	ExpectedAAGUID []byte
	AARoots        *x509.CertPool
}

// SubtleAttest is allows you to perform attestation without the guardrails provided by AppAttestImpl.
func SubtleAttest(in *SubtleAttestInput) Output {
	// unmarshal the attestation object
	attestObj := AttestationObject{}
	err := cbor.Unmarshal(in.AttestationInput.AttestationCBOR, &attestObj)
	if err != nil {
		return Output{Err: errors.Wrap(err, "unmarshalling attestation object")}
	}

	// ensure format is correct
	if attestObj.Format != Format {
		return Output{Err: fmt.Errorf("attestation object format mismatch: expected '%s', got '%s'", Format, attestObj.Format)}
	}

	// create a new cert verifier using the intermediates provided in the attestation object
	verifyOpts := x509.VerifyOptions{}
	if err := populateVerifyOpts(&verifyOpts, &attestObj, in.AARoots); err != nil {
		return Output{Err: errors.Wrap(err, "populating verify opts")}
	}
	verifyOpts.CurrentTime = in.Time

	// parse the leaf certificate
	leafCert, err := x509.ParseCertificate(attestObj.AttestationStatement.X509CertChain[0])
	if err != nil {
		return Output{Err: errors.Wrap(err, "parsing leaf certificate")}
	}

	// verify the leaf certificate
	_, err = leafCert.Verify(verifyOpts)
	if err != nil {
		return Output{Err: errors.Wrap(err, "verifying leaf certificate")}
	}

	// > 2. Create clientDataHash as the SHA256 hash of the one-time challenge your server sends
	// > to your app before performing the attestation,
	// > and append that hash to the end of the authenticator data (authData from the decoded object).
	// > 3. Generate a new SHA256 hash of the composite item to create nonce.
	nonce, err := ComputeNonce(attestObj.AuthData, in.AttestationInput.ServerChallenge)

	nonceFromCert, err := extractNonceFromCert(leafCert)
	if err != nil {
		return Output{Err: errors.Wrap(err, "extracting nonce from leaf certificate")}
	}

	if !bytes.Equal(nonceFromCert, nonce[:]) {
		return Output{Err: errors.New("nonce from cert did not match computed nonce")}
	}

	certPubKey, ok := leafCert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return Output{Err: fmt.Errorf("downcasting pubkey: unexpected type '%s'", reflect.TypeOf(leafCert.PublicKey))}
	}

	computedPubkeyHash := ComputeKeyHash(certPubKey)

	// assert that the public key of the leaf certificate matches the key handle returned by the app
	if !bytes.Equal(in.AttestationInput.KeyIdentifier, computedPubkeyHash[:]) {
		return Output{Err: errors.New("key identifier did not match public key of leaf certificate")}
	}

	authenticatorData := in.AttestationInput.OutAuthenticatorData
	if authenticatorData == nil {
		authenticatorData = &AuthenticatorData{}
	}

	if err = UnmarshalIntoAuthenticatorData(attestObj.AuthData, authenticatorData); err != nil {
		return Output{Err: errors.Wrap(err, "unmarshalling authenticator data")}
	}

	if !bytes.Equal(authenticatorData.RelayingPartyHash, in.BundleIDHash) {
		return Output{Err: errors.New("app id hash did not match relaying party hash")}
	}

	// ensure that AAGUID is correct
	if !bytes.Equal(in.ExpectedAAGUID, authenticatorData.AttestedCredentialData.AAGUID) {
		return Output{Err: errors.New("aaguid did not match - this attestation might have been generated for a different environment")}
	}

	// > 9. Verify that the authenticator data’s credentialId field is the same as the key identifier.
	if !bytes.Equal(in.AttestationInput.KeyIdentifier, authenticatorData.AttestedCredentialData.CredentialID) {
		return Output{Err: errors.New("key identifier did not match attested credential id of authenticator data")}
	}

	return Output{
		AuthenticatorData: authenticatorData,
		LeafCert:          leafCert,
	}
}

func populateVerifyOpts(dst *x509.VerifyOptions, attObj *AttestationObject, aaroots *x509.CertPool) (err error) {

	if len(attObj.AttestationStatement.X509CertChain) < 1 {
		return errors.New("expected at least one certificate in x509 cert chain")
	}

	// set the intermediates
	dst.Intermediates = x509.NewCertPool()
	// skip the first element, it's the leaf certificate
	for _, inter := range attObj.AttestationStatement.X509CertChain[1:] {
		cert, err := x509.ParseCertificate(inter)
		if err != nil {
			return errors.Wrap(err, "parsing intermediate")
		}
		dst.Intermediates.AddCert(cert)
		dst.Roots = aaroots
	}

	return nil
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

func ComputeNonce(authData, serverChallenge []byte) (res [sha256.Size]byte, err error) {
	nonceDigest := sha256.New()
	if _, err = nonceDigest.Write(authData); err != nil {
		err = errors.Wrap(err, "writing auth data to digest")
		return
	}

	// Heads up: this deviates from what the documentation says. The documentation says to append the checksum of the server challenge to the auth data
	// but in practice it appends the server challenge itself to the auth data.
	// I figured it out by comparing the expected values against the implementation-generated values.
	if _, err = nonceDigest.Write(serverChallenge); err != nil {
		err = errors.Wrap(err, "writing challenge checksum to digest")
		return
	}

	nonceDigest.Sum(res[:0])
	return
}

func ComputeKeyHash(key *ecdsa.PublicKey) [sha256.Size]byte {
	return sha256.Sum256(ellipticPointToX962Uncompressed(key))
}

var (
	NonceOID   = asn1.ObjectIdentifier{1, 2, 840, 113635, 100, 8, 2}
	AAGUIDProd = []byte("appattest\x00\x00\x00\x00\x00\x00\x00")
	AAGUIDDev  = []byte("appattestdevelop")
)

func init() {
	var err error
	if err != nil {
		panic(err)
	}
}
