// omniwitness-row interop verifier (docs/spec-conformance.md §8): parse a
// mosskeys-witness cosigned checkpoint and verify the log signature and the
// witness's 0x04 cosignature/v1 line through golang.org/x/mod/sumdb/note —
// the signed-note library omniwitness is built on.
//
// The 0x06 ML-DSA-44 line in the note is from an unknown key as far as this
// program is concerned and is ignored, exactly as omniwitness would ignore
// cosignature types it does not know.
//
// Usage: go run ./omniwitness <checkpoint note file> <witness vkey> <log vkey>
package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"os"
	"strconv"
	"strings"

	"golang.org/x/mod/sumdb/note"
)

// cosigVerifier is a note.Verifier for C2SP tlog-cosignature v1 Ed25519
// (signature type 0x04): the construction transparency-dev's witness
// package verifies for every checkpoint it countersigns.
type cosigVerifier struct {
	name    string
	keyHash uint32
	pk      ed25519.PublicKey
}

func (v cosigVerifier) Name() string    { return v.name }
func (v cosigVerifier) KeyHash() uint32 { return v.keyHash }

func (v cosigVerifier) Verify(msg, sig []byte) bool {
	// The timestamped_signature blob: u64 timestamp (big-endian) ||
	// ed25519 signature, over the cosignature/v1 domain-separated message.
	if len(sig) != 8+ed25519.SignatureSize {
		return false
	}
	timestamp := binary.BigEndian.Uint64(sig[:8])
	message := fmt.Sprintf("cosignature/v1\ntime %d\n%s", timestamp, msg)
	return ed25519.Verify(v.pk, []byte(message), sig[8:])
}

func fatal(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "interop-verify: "+format+"\n", args...)
	os.Exit(1)
}

func main() {
	if len(os.Args) != 4 {
		fatal("usage: omniwitness-verify <checkpoint note file> <witness vkey> <log vkey>")
	}
	noteBytes, err := os.ReadFile(os.Args[1])
	if err != nil {
		fatal("read checkpoint: %v", err)
	}

	// Parse the witness vkey: <name>+<8 hex key id>+<base64(0x04 || pk)>.
	parts := strings.SplitN(strings.TrimSpace(os.Args[2]), "+", 3)
	if len(parts) != 3 {
		fatal("malformed witness vkey: want <name>+<key id hex>+<base64 key>")
	}
	name, idHex, keyB64 := parts[0], parts[1], parts[2]
	raw, err := base64.StdEncoding.DecodeString(keyB64)
	if err != nil || len(raw) != 33 || raw[0] != 0x04 {
		fatal("witness vkey is not a 0x04 cosignature key")
	}

	// CS-08 agreement: the declared key id must be
	// SHA-256(name || "\n" || 0x04 || pk)[:4].
	h := sha256.New()
	h.Write([]byte(name))
	h.Write([]byte("\n"))
	h.Write([]byte{0x04})
	h.Write(raw[1:])
	keyHash := binary.BigEndian.Uint32(h.Sum(nil)[:4])
	declared, err := strconv.ParseUint(idHex, 16, 32)
	if err != nil || uint32(declared) != keyHash {
		fatal("witness vkey key id mismatch: declared %s, computed %08x", idHex, keyHash)
	}

	logVerifier, err := note.NewVerifier(os.Args[3])
	if err != nil {
		fatal("parse log vkey: %v", err)
	}

	cosig := cosigVerifier{name: name, keyHash: keyHash, pk: ed25519.PublicKey(raw[1:])}
	opened, err := note.Open(noteBytes, []note.Verifier{logVerifier, cosig})
	if err != nil {
		fatal("note verification failed: %v", err)
	}
	if len(opened.Sigs) != 2 {
		fatal("want 2 verified signatures (log + witness cosignature), got %d", len(opened.Sigs))
	}
	foundCosig := false
	for _, sig := range opened.Sigs {
		if sig.Name == name {
			foundCosig = true
		}
	}
	if !foundCosig {
		fatal("the witness cosignature did not verify")
	}

	origin, _, _ := strings.Cut(opened.Text, "\n")
	fmt.Printf("OK: x/mod note verified the log signature and the 0x04 cosignature from %s on origin %q\n", name, origin)
}
