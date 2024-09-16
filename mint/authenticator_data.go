package mint

import (
	"encoding/binary"
	"fmt"

	"github.com/fxamacker/cbor/v2"
	appattest "github.com/predicat-inc/go-app-attest"
)

func MarhsalAuthenticatorData(ad *appattest.AuthenticatorData) ([]byte, error) {
	if ad == nil {
		return nil, fmt.Errorf("AuthenticatorData pointer is nil")
	}

	adb := make([]byte, 0, 1024)

	// Serialize RelayingPartyHash (must be 32 bytes)
	if len(ad.RelayingPartyHash) != 32 {
		return nil, fmt.Errorf("RelayingPartyHash must be 32 bytes")
	}
	adb = append(adb, ad.RelayingPartyHash...)

	// Serialize Flags
	adb = append(adb, ad.Flags)

	// Serialize SignCount
	signCountBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(signCountBytes, ad.SignCount)
	adb = append(adb, signCountBytes...)

	// Serialize AttestedCredentialData if the flag is set
	if ad.Flags&appattest.ADF_HAS_ATTESTED_CREDENTIAL_DATA != 0 {
		err := marshalAttestedCredentialData(&ad.AttestedCredentialData, &adb)
		if err != nil {
			return nil, fmt.Errorf("failed to serialize AttestedCredentialData: %w", err)
		}
	}

	// authenticator extensions are not supported yet
	return adb, nil
}

func marshalAttestedCredentialData(acd *appattest.AttestedCredentialData, dst *[]byte) error {

	// Serialize AAGUID (must be 16 bytes)
	if len(acd.AAGUID) != 16 {
		return fmt.Errorf("AAGUID must be 16 bytes")
	}
	*dst = append(*dst, acd.AAGUID...)

	// Serialize CredentialID length (2 bytes) and CredentialID
	credIDLenBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(credIDLenBytes, uint16(len(acd.CredentialID)))
	*dst = append(*dst, credIDLenBytes...)
	*dst = append(*dst, acd.CredentialID...)

	// Serialize CredentialPublicKey
	keyBytes, err := cbor.Marshal(acd.CredentialPublicKey)
	if err != nil {
		return fmt.Errorf("failed to serialize CredentialPublicKey: %w", err)
	}
	*dst = append(*dst, keyBytes...)

	return nil
}
