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
go get github.com/predicat-inc/go-app-attest
```

## Usage

Here's a basic example of how to use go-app-attest:

```go
package main

import (
	"encoding/base64"
	"fmt"
	"log"

	appattest "github.com/predicat-inc/go-app-attest"
)

func main() {
	// Create an attestor
	bundleIDHash := sha256.Sum256([]byte("ABC6DEF.com.example.my.bundleid"))
	attestor, err := appattest.New(
		appattest.WithBundleIDHash(bundleIDHash[:]),
		appattest.WithEnvironment(appattest.EnvironmentProd),
	)
	if err != nil {
		log.Fatalf("creating attestor: %v", err)
	}

	// Prepare attestation input
	req := appattest.Input{
		ServerChallenge: []byte("YOUR_SERVER_CHALLENGE"),
		AttestationCBOR: []byte("YOUR_ATTESTATION_DATA"),
		KeyIdentifier:   []byte("YOUR_ATTESTED_KEY_IDENTIFIER"),
	}

	// Perform attestation
	res := attestor.Attest(&req)
	if res.Err != nil {
		log.Fatalf("attestation: %v", res.Err)
	}

	fmt.Printf("Attestation successful. Sign count: %d\n", res.AuthenticatorData.SignCount)
}
```

## Configuration Options

The `New` function accepts several configuration options:

- `WithBundleIDHash(hash)`: Set the expected bundle ID hash (required)
- `WithEnvironment(env)`: Set the environment (Production or Development) (default: Production)
- `WithAppAttestRoots(pool)`: Provide custom certificate roots (default: Apple AppAttest root certificates)
- `WithNowFn(fn)`: Provide a custom time function (default: time.Now)
- `WithConstructInto(*attestor)`: Construct the attestor into an existing zero struct (default: nil)

## Testing

The package includes tests. To run them, use:

```bash
go test ./...
```

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This library is licensed under GPLv3. See [LICENSE](./LICENSE) for more information.
