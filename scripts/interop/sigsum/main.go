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

	// The checkpoint (origin, size, root, log signature), then the
	// cosignature lines — the same parse order sigsum's own witness uses.
	reader := strings.NewReader(string(noteBytes))
	var cp checkpoint.Checkpoint
	if err := cp.FromASCII(reader); err != nil {
		fatal("parse checkpoint: %v", err)
	}
	if err := cp.Verify(&logKey.PublicKey); err != nil {
		fatal("log signature verification failed: %v", err)
	}
	cosigs, err := checkpoint.CosignatureLinesFromASCII(reader)
	if err != nil {
		fatal("parse cosignature lines: %v", err)
	}
	if _, err := cp.VerifyCosignatureByKey(cosigs, &witnessKey.PublicKey); err != nil {
		fatal("witness cosignature verification failed: %v", err)
	}

	fmt.Printf("OK: sigsum-go verified the log signature and the 0x04 cosignature from %s on origin %q\n", witnessKey.Name, cp.Origin)
}
