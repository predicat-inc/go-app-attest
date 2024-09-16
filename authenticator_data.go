package appattest

import (
	"bytes"
	"encoding/binary"

	"github.com/fxamacker/cbor/v2"
	cose_key "github.com/ldclabs/cose/key"
)

const (
	ADF_USER_PRESENT                 = byte(1)
	ADF_USER_VERIFIED                = byte(1 << 2)
	ADF_HAS_ATTESTED_CREDENTIAL_DATA = byte(1 << 6)
	ADF_HAS_EXTENSION_DATA           = byte(1 << 7)
)

type AuthenticatorData struct {
	RelayingPartyHash      []byte
	Flags                  byte
	SignCount              uint32
	AttestedCredentialData AttestedCredentialData
	// Extensions (ignored)
}

type AttestedCredentialData struct {
	AAGUID              []byte
	CredentialID        []byte
	CredentialPublicKey cose_key.Key
}

func UnmarshalIntoAuthenticatorData(src []byte, dst *AuthenticatorData) error {
	dst.RelayingPartyHash = src[0:32]
	dst.Flags = src[32]
	dst.SignCount = binary.BigEndian.Uint32(src[33:37])

	if dst.Flags&ADF_HAS_ATTESTED_CREDENTIAL_DATA != 0 {
		var err error
		_, err = UnmarshalIntoAttestedCredentialData(src[37:], &dst.AttestedCredentialData)
		if err != nil {
			return err
		}
	}

	// ignoring extensions
	return nil
}

func UnmarshalIntoAttestedCredentialData(src []byte, dst *AttestedCredentialData) (rest []byte, err error) {
	dst.AAGUID = src[0:16]

	credLen := binary.BigEndian.Uint16(src[16:18])
	dst.CredentialID = src[18 : 18+credLen]

	dec := cbor.NewDecoder(bytes.NewReader(src[18+credLen:]))

	if err := dec.Decode(&dst.CredentialPublicKey); err != nil {
		return nil, err
	}

	return src[18+int(uint(credLen))+dec.NumBytesRead():], err
}
