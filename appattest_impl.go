package appattest

import (
	"crypto/x509"
	"fmt"
	"time"

	"github.com/pkg/errors"
)

const appattestRootCAPEM = `-----BEGIN CERTIFICATE-----
MIICITCCAaegAwIBAgIQC/O+DvHN0uD7jG5yH2IXmDAKBggqhkjOPQQDAzBSMSYw
JAYDVQQDDB1BcHBsZSBBcHAgQXR0ZXN0YXRpb24gUm9vdCBDQTETMBEGA1UECgwK
QXBwbGUgSW5jLjETMBEGA1UECAwKQ2FsaWZvcm5pYTAeFw0yMDAzMTgxODMyNTNa
Fw00NTAzMTUwMDAwMDBaMFIxJjAkBgNVBAMMHUFwcGxlIEFwcCBBdHRlc3RhdGlv
biBSb290IENBMRMwEQYDVQQKDApBcHBsZSBJbmMuMRMwEQYDVQQIDApDYWxpZm9y
bmlhMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAERTHhmLW07ATaFQIEVwTtT4dyctdh
NbJhFs/Ii2FdCgAHGbpphY3+d8qjuDngIN3WVhQUBHAoMeQ/cLiP1sOUtgjqK9au
Yen1mMEvRq9Sk3Jm5X8U62H+xTD3FE9TgS41o0IwQDAPBgNVHRMBAf8EBTADAQH/
MB0GA1UdDgQWBBSskRBTM72+aEH/pwyp5frq5eWKoTAOBgNVHQ8BAf8EBAMCAQYw
CgYIKoZIzj0EAwMDaAAwZQIwQgFGnByvsiVbpTKwSga0kP0e8EeDS4+sQmTvb7vn
53O5+FRXgeLhpJ06ysC5PrOyAjEAp5U4xDgEgllF7En3VcE3iexZZtKeYnpqtijV
oyFraWVIyd/dganmrduC1bmTBGwD
-----END CERTIFICATE-----`

type AttestorImpl struct {
	aaroots              *x509.CertPool
	nowfn                func() time.Time
	expectedAAGUID       []byte
	expectedBundleIDHash []byte
}

type optionsState struct {
	into *AttestorImpl

	aaroots      *x509.CertPool
	nowfn        func() time.Time
	bundleIDHash []byte

	// defaults to prod
	environment Environment
}

type option struct {
	apply func(*optionsState)
}

func newoption(fn func(*optionsState)) option {
	return option{
		apply: fn,
	}
}

func WithEnvironment(env Environment) option {
	return newoption(func(os *optionsState) {
		os.environment = env
	})
}

// WithConstructInto lets the user provide a zero struct for initialization.
func WithConstructInto(into *AttestorImpl) option {
	return newoption(func(s *optionsState) {
		s.into = into
	})
}

// WithAppAttestRoots lets the user provide its own authoritative certs pool
func WithAppAttestRoots(pool *x509.CertPool) option {
	return newoption(func(s *optionsState) {
		s.aaroots = pool
	})
}

func WithNowFn(now func() time.Time) option {
	return newoption(func(os *optionsState) {
		os.nowfn = now
	})
}

func WithBundleIDHash(hash []byte) option {
	return newoption(func(os *optionsState) {
		os.bundleIDHash = hash
	})
}

func New(options ...option) (*AttestorImpl, error) {
	optionsState := optionsState{}

	for _, option := range options {
		option.apply(&optionsState)
	}

	// determine instanstiation destination
	var att *AttestorImpl
	if optionsState.into == nil {
		att = &AttestorImpl{}
	} else {
		att = optionsState.into
	}

	// determine pool
	if optionsState.aaroots == nil {
		// use the certificate provided by the library
		att.aaroots = x509.NewCertPool()
		if !att.aaroots.AppendCertsFromPEM([]byte(appattestRootCAPEM)) {
			return nil, errors.New("loading library provided app attest ca")
		}
	} else {
		// use the user provided pool
		att.aaroots = optionsState.aaroots
	}

	// determine timefn
	if optionsState.nowfn == nil {
		att.nowfn = time.Now
	} else {
		att.nowfn = optionsState.nowfn
	}

	// determine expected AAGUID
	switch optionsState.environment {
	case EnvironmentProd:
		att.expectedAAGUID = AAGUIDProd
	case EnvironmentDev:
		att.expectedAAGUID = AAGUIDDev
	default:
		return nil, fmt.Errorf("unknown environment %v", optionsState.environment)
	}

	// determine bundle id hash
	if optionsState.bundleIDHash == nil {
		return nil, fmt.Errorf("bundle id hash must be provided")
	} else {
		att.expectedBundleIDHash = optionsState.bundleIDHash
	}

	return att, nil
}

func (at *AttestorImpl) Attest(in *Input) Output {
	subtleIn := SubtleAttestInput{
		AttestationInput: in,

		BundleIDHash:   at.expectedBundleIDHash,
		Time:           at.nowfn(),
		ExpectedAAGUID: at.expectedAAGUID,
		AARoots:        at.aaroots,
	}
	return SubtleAttest(&subtleIn)
}
