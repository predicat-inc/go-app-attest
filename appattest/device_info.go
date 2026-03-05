package appattest

import (
	"crypto/x509"
	"encoding/asn1"
)

var (
	oidDeviceInfo = asn1.ObjectIdentifier{1, 2, 840, 113635, 100, 8, 7}
)

// DeviceClass represents the device class value from the attestation
// certificate (ASN.1 tag [1104]).
type DeviceClass = int

const (
	// DeviceClassiPad indicates an iPad device.
	DeviceClassiPad DeviceClass = 0

	// DeviceClassiPhone indicates an iPhone device.
	DeviceClassiPhone DeviceClass = 2
)

// DeviceInfo contains device and OS information extracted from the Apple App
// Attest leaf certificate extension OID 1.2.840.113635.100.8.7. This extension
// is undocumented by Apple; the field meanings are reverse-engineered and
// best-effort. All fields are optional.
type DeviceInfo struct {
	// OSVersion is the iOS/iPadOS version string (e.g. "18.0", "26.3").
	// ASN.1 tag [1400].
	OSVersion string

	// OSBuild is the OS build identifier (e.g. "22A244b", "23D127").
	// ASN.1 tag [1403].
	OSBuild string

	// DeviceClass indicates the device type (DeviceClassiPad,
	// DeviceClassiPhone). May contain other values in non-production
	// environments. Nil if absent. ASN.1 tag [1104].
	DeviceClass *DeviceClass

	// IBootVersion is the iBoot/SEP version string (e.g. "1.0.213").
	// Only observed on newer OS versions. ASN.1 tag [1401].
	IBootVersion string

	// SEPVersion is the SEP firmware version string (e.g. "23.4.127.0.0,0").
	// ASN.1 tag [1418].
	SEPVersion string

	// Platform is the platform identifier (e.g. "iphoneos").
	// ASN.1 tag [1026].
	Platform string

	// BuildVariant is the build variant (e.g. "Internal"). Only present on
	// Apple internal builds. ASN.1 tag [1029].
	BuildVariant string
}

// parseDeviceInfo attempts to extract DeviceInfo from the leaf certificate.
// Returns nil if the extension is not present. Parsing is best-effort:
// unrecognized or malformed fields are silently skipped.
func parseDeviceInfo(cert *x509.Certificate) *DeviceInfo {
	var extValue []byte
	for _, ext := range cert.Extensions {
		if ext.Id.Equal(oidDeviceInfo) {
			extValue = ext.Value
			break
		}
	}
	if extValue == nil {
		return nil
	}

	// The extension value is a SEQUENCE of context-specific constructed
	// tagged values. We parse the outer SEQUENCE then walk each child.
	var seq asn1.RawValue
	rest, err := asn1.Unmarshal(extValue, &seq)
	if err != nil || len(rest) > 0 || !seq.IsCompound {
		return nil
	}

	di := &DeviceInfo{}
	data := seq.Bytes
	for len(data) > 0 {
		var item asn1.RawValue
		data, err = asn1.Unmarshal(data, &item)
		if err != nil {
			break
		}
		if item.Class != asn1.ClassContextSpecific || !item.IsCompound {
			continue
		}

		switch item.Tag {
		case 1400:
			di.OSVersion = extractString(item.Bytes)
		case 1403:
			di.OSBuild = extractString(item.Bytes)
		case 1104:
			if v, ok := extractInt(item.Bytes); ok {
				di.DeviceClass = &v
			}
		case 1401:
			di.IBootVersion = extractString(item.Bytes)
		case 1418:
			di.SEPVersion = extractString(item.Bytes)
		case 1026:
			di.Platform = extractString(item.Bytes)
		case 1029:
			di.BuildVariant = extractString(item.Bytes)
		}
	}

	return di
}

// extractString parses a single ASN.1 OCTET STRING from the given bytes
// and returns it as a string.
func extractString(b []byte) string {
	var raw asn1.RawValue
	if _, err := asn1.Unmarshal(b, &raw); err != nil {
		return ""
	}
	return string(raw.Bytes)
}

// extractInt parses a single ASN.1 INTEGER from the given bytes.
func extractInt(b []byte) (int, bool) {
	var val int
	if _, err := asn1.Unmarshal(b, &val); err != nil {
		return 0, false
	}
	return val, true
}
