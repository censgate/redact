// Standalone standard-library generator for fake platform-v1 golden values.
// The fixed Ed25519 seed is test-only and carries no service credentials.
// On Go 1.26+, set GODEBUG=cryptocustomrand=1 so ecdsa.SignASN1 uses the
// deterministic test reader supplied below.
package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
)

func main() {
	eventID := "test-record-1"
	timestamp := "2025-01-02T03:04:05Z"
	// encoding/json sorts string map keys and applies Go's default HTML escaping.
	canonicalObject := map[string]any{
		"action": "chat", "boundary": "", "caller": "test-principal",
		"content_sha256": "", "destination_class": "", "destination_id": "",
		"destination_vendor": "", "entity_types": []string(nil), "epoch": "",
		"error_type": "", "event_id": eventID, "event_name": "test.event",
		"gateway_instance": "", "outcome": "allowed", "profile": "strict",
		"redactions": 0, "region": "test-region", "session_id": "", "shard": "",
		"span_id": "", "subject_ref": "", "tenant_id": "test-tenant",
		"timestamp": timestamp, "tokens_issued": 0, "trace_id": "",
	}
	canonical, err := json.Marshal(canonicalObject)
	must(err)
	genesis := "0000000000000000000000000000000000000000000000000000000000000000"
	hashInput := append([]byte(genesis), canonical...)
	hashInput = append(hashInput, []byte(eventID)...)
	hashInput = append(hashInput, []byte(timestamp)...)
	digest := sha256.Sum256(hashInput)
	recordHash := hex.EncodeToString(digest[:])

	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = 7
	}
	private := ed25519.NewKeyFromSeed(seed)
	recordInput := []byte(fmt.Sprintf("test-chain|1|%s", recordHash))
	recordSignature := ed25519.Sign(private, recordInput)
	ed25519DER, err := x509.MarshalPKIXPublicKey(private.Public())
	must(err)
	ed25519PEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: ed25519DER})
	p256Public, p256Signature := ecdsaGolden(elliptic.P256(), []byte("anchor-root|v1|test-root"))
	p384Public, p384Signature := ecdsaGolden(elliptic.P384(), []byte("anchor-root|v1|test-root"))
	result := map[string]string{
		"canonical_json":     string(canonical),
		"record_hash":        recordHash,
		"record_signature":   base64.StdEncoding.EncodeToString(recordSignature),
		"signature_input":    string(recordInput),
		"trusted_public_key": hex.EncodeToString(private.Public().(ed25519.PublicKey)),
		"ed25519_public_pem": string(ed25519PEM),
		"p256_public_pem":    string(p256Public),
		"p256_signature":     base64.StdEncoding.EncodeToString(p256Signature),
		"p384_public_pem":    string(p384Public),
		"p384_signature":     base64.StdEncoding.EncodeToString(p384Signature),
	}
	output, err := json.MarshalIndent(result, "", "  ")
	must(err)
	fmt.Println(string(output))
}

func ecdsaGolden(curve elliptic.Curve, message []byte) ([]byte, []byte) {
	// Scalar one is a deliberately public test-only private key input.
	d := big.NewInt(1)
	x, y := curve.ScalarBaseMult(d.Bytes())
	private := &ecdsa.PrivateKey{PublicKey: ecdsa.PublicKey{Curve: curve, X: x, Y: y}, D: d}
	der, err := x509.MarshalPKIXPublicKey(&private.PublicKey)
	must(err)
	publicPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
	digest := sha256.Sum256(message)
	randomness := bytes.NewReader(bytes.Repeat([]byte{0x42}, 4096))
	signature, err := ecdsa.SignASN1(randomness, private, digest[:])
	must(err)
	return publicPEM, signature
}

func must(err error) {
	if err != nil {
		panic(err)
	}
}
