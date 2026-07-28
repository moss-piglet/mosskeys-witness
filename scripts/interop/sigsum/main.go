// sigsum-row interop verifier (docs/spec-conformance.md §8): sigsum-go's
// pkg/checkpoint parses our served checkpoint, verifies the log signature,
// and verifies our 0x04 witness cosignature via VerifyCosignatureByKey —
// the same calls a sigsum witness/monitor makes — and sigsum-go's witness
// key-id formula must agree with our vkey's declared key id.
//
// Usage: go run ./sigsum <checkpoint note file> <witness vkey> <log vkey>
package main

import (
	"fmt"
	"os"
	"strings"

	"sigsum.org/sigsum-go/pkg/checkpoint"
)

func fatal(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "interop-verify: "+format+"\n", args...)
	os.Exit(1)
}

func main() {
	if len(os.Args) != 4 {
		fatal("usage: sigsum-verify <checkpoint note file> <witness vkey> <log vkey>")
	}
	noteBytes, err := os.ReadFile(os.Args[1])
	if err != nil {
		fatal("read checkpoint: %v", err)
	}

	var witnessKey, logKey checkpoint.NoteVerifier
	if err := witnessKey.FromString(strings.TrimSpace(os.Args[2])); err != nil {
		fatal("parse witness vkey: %v", err)
	}
	if err := logKey.FromString(strings.TrimSpace(os.Args[3])); err != nil {
		fatal("parse log vkey: %v", err)
	}
	if witnessKey.Type != checkpoint.SigTypeCosignature {
		fatal("witness vkey is not a 0x04 cosignature key (type 0x%02x)", byte(witnessKey.Type))
	}

	// CS-08 agreement: sigsum-go's witness key-id formula must reproduce
	// the key id our vkey declares.
	if got := checkpoint.NewWitnessKeyId(witnessKey.Name, &witnessKey.PublicKey); got != witnessKey.KeyId {
		fatal("witness vkey key id mismatch: declared %x, sigsum-go computed %x", witnessKey.KeyId, got)
	}

	// Split the note at the blank line: the checkpoint text above it, the
	// signature lines below it. cp.FromASCII consumes every signature line
	// (the cosignatures are skipped as unwanted), so the cosignature lines
	// are parsed separately from the section below the blank line —
	// CosignatureLinesFromASCII rejects the non-signature text lines.
	_, sigLines, found := strings.Cut(string(noteBytes), "\n\n")
	if !found {
		fatal("malformed note: no blank line before the signatures")
	}

	var cp checkpoint.Checkpoint
	if err := cp.FromASCII(strings.NewReader(string(noteBytes))); err != nil {
		fatal("parse checkpoint: %v", err)
	}
	// pkg/checkpoint reconstructs the signed checkpoint text from the log
	// public key with the sigsum origin convention
	// (sigsum.org/v1/tree/<sha256(pubkey)>), so this only verifies for a
	// log whose origin follows that convention — the test's log does.
	if err := cp.Verify(&logKey.PublicKey); err != nil {
		fatal("log signature verification failed: %v", err)
	}
	cosigs, err := checkpoint.CosignatureLinesFromASCII(strings.NewReader(sigLines))
	if err != nil {
		fatal("parse cosignature lines: %v", err)
	}
	if _, err := cp.VerifyCosignatureByKey(cosigs, &witnessKey.PublicKey); err != nil {
		fatal("witness cosignature verification failed: %v", err)
	}

	fmt.Printf("OK: sigsum-go verified the log signature and the 0x04 cosignature from %s on origin %q\n", witnessKey.Name, cp.Origin)
}
