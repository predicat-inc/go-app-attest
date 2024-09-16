package mint_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"testing"
	"time"

	appattest "github.com/predicat-inc/go-app-attest"
	"github.com/predicat-inc/go-app-attest/mint"
	"github.com/stretchr/testify/require"
)

func TestMint(t *testing.T) {
	appIDDigest := sha256.Sum256([]byte("myapp"))

	cader, capriv, err := generateCACert("mock ca")
	require.NoError(t, err)

	intder, intpriv, err := generateIntermediateCert("mock intermediate", cader, capriv)
	require.NoError(t, err)

	intCert, err := x509.ParseCertificate(intder)
	require.NoError(t, err)

	attKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	mintout := mint.Mint(&mint.Input{
		IntermediatesDER:  [][]byte{intder},
		IssuerCertificate: intCert,
		IssuerKey:         intpriv,
		AttestedKey:       &attKey.PublicKey,
		AAGUID:            appattest.AAGUIDDev,

		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(time.Hour),

		BundleIDHash:    appIDDigest[:],
		ServerChallenge: []byte("server data"),
	})
	require.NoError(t, mintout.Err)

	caCert, err := x509.ParseCertificate(cader)
	require.NoError(t, err)

	keyid := appattest.ComputeKeyHash(&attKey.PublicKey)

	caPool := x509.NewCertPool()
	caPool.AddCert(caCert)
	attestout := appattest.SubtleAttest(&appattest.SubtleAttestInput{
		AttestationInput: &appattest.Input{
			ServerChallenge: []byte("server data"),
			AttestationCBOR: mintout.Attestation,
			KeyIdentifier:   keyid[:],
		},
		BundleIDHash:   appIDDigest[:],
		ExpectedAAGUID: appattest.AAGUIDDev,
		Time:           time.Now(),
		AARoots:        caPool,
	})
	require.NoError(t, attestout.Err)
}
