# go-app-attest

go-app-attest is a Go package for implementing Apple App Attestation. This library provides functionality to verify the authenticity and integrity of apps running on Apple devices.

## Features

- Attestation verification for both production and development environments
- Support for custom certificate pools and time functions
- Detailed error reporting
- Extraction of attested certificate, public key and authenticator data

## Installation

To install go-app-attest, use the following command:

```bash
go get github.com/splitsecure/go-app-attest
```

## Usage

Here's a basic example of how to use go-app-attest:

```go
package main

import (
	"encoding/base64"
	"fmt"
	"log"

	appattest "github.com/splitsecure/go-app-attest"
)

func main() {
	// Create an attestor
	bundleDigest := sha256.Sum256([]byte("ABC6DEF.com.example.my.bundleid"))
	attestor, err := appattest.New()
	if err != nil {
		log.Fatalf("creating attestor: %v", err)
	}

	// Prepare attestation input
	req := appattest.VerifyAttestationInput{
		ServerChallenge: []byte("YOUR_SERVER_CHALLENGE"),
		AttestationCBOR: []byte("YOUR_ATTESTATION_DATA"),
	}

	// Perform attestation
	res := attestor.VerifyAttestation(&req)
	if res.Err != nil {
		log.Fatalf("attestation: %v", res.Err)
	}

	// Verify provenance
	if !bytes.Equal(res.EnvironmentGUID, appattest.AAGUIDProd) {
		log.Fatalf("attestation: issuer is not App Attest Prod")
	}

	if !bytes.Equal(res.BundleDigest, bundleDigest[:]) {
		log.Fatalf("attestation: attested bundle differs from the expected one")
	}

	// Verify validity instant
	instant := time.Now()
	if !(instant.After(res.LeafCert.NotBefore) && instant.Before(res.LeafCert.NotAfter)) {
		log.Fatalf("attestation: not valid at expected time")
	}

	// (optional) verify the key id of the signer
	expectedKeyID := []byte("myexpectedkeyid")
	if !bytes.Equal(expectedKeyID, res.KeyID) {
		log.Fatalf("attestation: unexpected signer id ")
	}


	fmt.Printf("Attestation successful. Sign count: %d\n", res.AuthenticatorData.SignCount)
}
```

## Configuration Options

The `New` function accepts several configuration options:

- `WithAppAttestRoots(pool)`: Provide custom certificate roots (default: Apple AppAttest root certificates)
- `WithNowFn(fn)`: Provide a custom time function (default: time.Now)

## Testing

The package includes tests. To run them, use:

```bash
go test ./...
```

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This library is licensed under GPLv3. See [LICENSE](./LICENSE) for more information.
