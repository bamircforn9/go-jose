package jose

import "golang.org/x/text/unicode/norm"

// JSONWebKey represents a public or private key in JWK format.
type JSONWebKey struct {
	KeyID string
	Key   interface{}
}

// JSONWebKeySet represents a set of JWKs.
type JSONWebKeySet struct {
	Keys []JSONWebKey
}

// Key searches in the set for keys associated with the given key ID.
// It normalizes both the query kid and the candidate key's KeyID to NFC before comparing.
func (s *JSONWebKeySet) Key(kid string) []JSONWebKey {
	var keys []JSONWebKey
	normalizedKid := norm.NFC.String(kid)
	for _, key := range s.Keys {
		if norm.NFC.String(key.KeyID) == normalizedKid {
			keys = append(keys, key)
		}
	}
	return keys
}
