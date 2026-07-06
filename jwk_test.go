package jose

import (
	"testing"
)

func TestJWKSetLookupUnicodeNormalization(t *testing.T) {
	// NFC: "café" is "caf\u00e9"
	// NFD: "café" is "cafe\u0301"
	nfcKid := "caf\u00e9"
	nfdKid := "cafe\u0301"

	// Test case 1: Key in JWK set has NFC kid, queried with NFD kid
	nfcKey := JSONWebKey{
		KeyID: nfcKid,
		Key:   []byte("dummy-key-1"),
	}
	nfcSet := JSONWebKeySet{
		Keys: []JSONWebKey{nfcKey},
	}

	keys := nfcSet.Key(nfdKid)
	if len(keys) != 1 || keys[0].KeyID != nfcKid {
		t.Errorf("expected to find key with NFC kid when querying with NFD kid")
	}

	// Test case 2: Key in JWK set has NFD kid, queried with NFC kid
	nfdKey := JSONWebKey{
		KeyID: nfdKid,
		Key:   []byte("dummy-key-2"),
	}
	nfdSet := JSONWebKeySet{
		Keys: []JSONWebKey{nfdKey},
	}

	keys = nfdSet.Key(nfcKid)
	if len(keys) != 1 || keys[0].KeyID != nfdKid {
		t.Errorf("expected to find key with NFD kid when querying with NFC kid")
	}

	// Test case 3: Standard ASCII kid
	asciiKey := JSONWebKey{
		KeyID: "standard-ascii",
		Key:   []byte("dummy-key-3"),
	}
	asciiSet := JSONWebKeySet{
		Keys: []JSONWebKey{asciiKey},
	}

	keys = asciiSet.Key("standard-ascii")
	if len(keys) != 1 || keys[0].KeyID != "standard-ascii" {
		t.Errorf("expected to find key with standard ASCII kid")
	}

	// Test case 4: Empty string
	keys = asciiSet.Key("")
	if len(keys) != 0 {
		t.Errorf("expected no keys for empty string query")
	}

	// Test case 5: Invalid UTF-8 sequence
	invalidKid := "invalid-\xff-sequence"
	invalidKey := JSONWebKey{
		KeyID: invalidKid,
		Key:   []byte("dummy-key-4"),
	}
	invalidSet := JSONWebKeySet{
		Keys: []JSONWebKey{invalidKey},
	}
	keys = invalidSet.Key(invalidKid)
	if len(keys) != 1 || keys[0].KeyID != invalidKid {
		t.Errorf("expected to find key with invalid UTF-8 sequence when queried with exact same sequence")
	}
}
