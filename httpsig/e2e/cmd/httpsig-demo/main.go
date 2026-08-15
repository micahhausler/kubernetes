/*
Copyright The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

// Command httpsig-demo plays both sides of the demo's key handling.
//
//	credential  the exec credential plugin kubectl runs, returning signing
//	            material rather than a token
//	derive      the broker's half: fold the root secret down to the date step
//	            and print the rung the API server holds
//	ladder      print the derivation ladder, which both configurations state
//
// One program because the three share a definition they must agree on. A broker
// that folded the ladder differently from the client would produce a key the
// server cannot verify, and the failure would be a bare signature mismatch.
//
// It is Go rather than a shell script for two reasons. The credential output is
// built from the real ExecCredential types, so a field name cannot drift from
// the API it has to satisfy. And the derivation is the library's own, so the
// demo cannot disagree with the server about what the ladder means.
package main

import (
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/micahhausler/httpsig/keyscope"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	clientauthv1 "k8s.io/client-go/pkg/apis/clientauthentication/v1"
	"sigs.k8s.io/yaml"
)

// The ladder, stated once for every party that derives through it.
//
// The shape follows the SigV4 pattern: a prefix on the root secret, a date step,
// and a terminator literal for domain separation. The date step is what bounds a
// derived key to one UTC day.
//
// A scope step obliges every holder to state a value for it, so both the broker
// and the client name their cluster. Nothing from the keyid ever feeds
// derivation: a scope value comes only from the holder's own stage, which is what
// makes the keyid's scope segments an assertion to compare rather than an input
// to trust.
var ladder = keyscope.Derivation{
	Kind:         "hmac-ladder",
	Hash:         "sha-256",
	SecretPrefix: "K8S1",
	Steps: []keyscope.Step{
		{Name: "date", Date: "YYYYMMDD"},
		{Name: "cluster", Scope: true},
		{Name: "terminator", Literal: "k8s1_request"},
	},
}

// The step the API server's key is folded through. Naming it once keeps the
// derive subcommand and the stage it prints from disagreeing.
//
// Through the cluster step rather than only the date. Either way the server folds
// the cluster value from its own configuration, so both are cluster bound in
// effect; folding it into the material means the bytes themselves are useless for
// another cluster, not merely unused for one.
const serverRungStep = "cluster"

const (
	hmacKeyID  = "demo-hmac"
	ecdsaKeyID = "demo-ecdsa-p384"
)

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	var err error
	switch os.Args[1] {
	case "credential":
		err = credential(os.Args[2:])
	case "derive":
		err = derive(os.Args[2:])
	case "ladder":
		err = printLadder(os.Args[2:])
	default:
		usage()
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "httpsig-demo %s: %v\n", os.Args[1], err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: httpsig-demo {credential|derive|ladder} [flags]")
	os.Exit(2)
}

// ladderYAML renders the ladder for both configurations to embed.
//
// One rendering serves both because the kubeconfig type and the API server type
// are field-identical to the library's by construction, which an in-tree
// reflection test asserts. If that ever stops being true, this has to split in
// two, and that test is what will say so.
func ladderYAML(indent string) (string, error) {
	out, err := yaml.Marshal(ladder)
	if err != nil {
		return "", err
	}
	lines := strings.Split(strings.TrimRight(string(out), "\n"), "\n")
	for i, line := range lines {
		lines[i] = indent + line
	}
	return strings.Join(lines, "\n"), nil
}

func printLadder(args []string) error {
	fs := flag.NewFlagSet("ladder", flag.ExitOnError)
	indent := fs.String("indent", "", "prefix every line with this string")
	if err := fs.Parse(args); err != nil {
		return err
	}
	out, err := ladderYAML(*indent)
	if err != nil {
		return err
	}
	fmt.Println(out)
	return nil
}

// derive is the broker. It holds the root secret, folds it down to the date
// step, and hands out the result. The API server gets that rung and never sees
// the root, which bounds what a compromised API server can forge: only for the
// one day the rung names.
func derive(args []string) error {
	fs := flag.NewFlagSet("derive", flag.ExitOnError)
	secretFile := fs.String("secret-file", "", "file holding the root secret")
	cluster := fs.String("cluster", "", "value for the ladder's cluster scope step")
	day := fs.String("date", "", "date to bind the key to, YYYYMMDD (default today, UTC)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *secretFile == "" {
		return fmt.Errorf("--secret-file is required")
	}
	if *cluster == "" {
		return fmt.Errorf("--cluster is required")
	}
	secret, err := readSecret(*secretFile)
	if err != nil {
		return err
	}

	at := time.Now().UTC()
	if *day != "" {
		// Parsed rather than passed through, so a malformed date fails here
		// instead of becoming a key nothing can verify.
		at, err = time.Parse("20060102", *day)
		if err != nil {
			return fmt.Errorf("--date %q is not YYYYMMDD: %w", *day, err)
		}
	}

	// The root holder's own position: the whole ladder ahead of it, and a value
	// for every scope step in it.
	root, err := keyscope.New(ladder, keyscope.Stage{
		Name:  hmacKeyID,
		Scope: map[string]string{"cluster": *cluster},
	}, secret)
	if err != nil {
		return err
	}
	material, stage, err := root.Derive(serverRungStep, at)
	if err != nil {
		return err
	}

	// The stage comes back from the library rather than being assembled here.
	// Hand-writing it would be a second statement of where the rung sits, and
	// the two could disagree.
	return json.NewEncoder(os.Stdout).Encode(struct {
		Date  string            `json:"date"`
		Rung  string            `json:"rung"`
		From  string            `json:"from"`
		Scope map[string]string `json:"scope"`
	}{
		Date:  at.Format("20060102"),
		Rung:  base64.StdEncoding.EncodeToString(material),
		From:  stage.From,
		Scope: stage.Scope,
	})
}

// credential is the exec credential plugin. kubectl passes an ExecCredential in
// KUBERNETES_EXEC_INFO whose spec says which algorithm the client is configured
// for, and this answers with material of that kind. One plugin serves both keys,
// which is why the kubeconfig never names which key it holds.
//
// Everything it returns is hardcoded. A real one would call a provider, mint
// something short lived, and set status.expirationTimestamp so kubectl knows
// when to ask again.
func credential(args []string) error {
	fs := flag.NewFlagSet("credential", flag.ExitOnError)
	fixtures := fs.String("fixtures", "", "directory holding the client's key material")
	cluster := fs.String("cluster", "", "value for the ladder's cluster scope step")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *fixtures == "" {
		return fmt.Errorf("--fixtures is required")
	}

	raw := os.Getenv("KUBERNETES_EXEC_INFO")
	if raw == "" {
		return fmt.Errorf("KUBERNETES_EXEC_INFO is unset, so this was not run as a credential plugin")
	}
	var in clientauthv1.ExecCredential
	if err := json.Unmarshal([]byte(raw), &in); err != nil {
		return fmt.Errorf("decoding KUBERNETES_EXEC_INFO: %w", err)
	}
	if in.Spec.HTTPSignature == nil {
		return fmt.Errorf("the client asked for a token, not a signature; add an httpSignature block to this kubeconfig user")
	}
	// The client states which headers it covers, and every one needs a value.
	// Failing here beats returning a credential the client will refuse.
	if len(in.Spec.HTTPSignature.SignedHeaders) > 0 {
		return fmt.Errorf("this demo has no values for the signed headers the client covers")
	}

	out := clientauthv1.ExecCredential{
		TypeMeta: metav1.TypeMeta{
			APIVersion: clientauthv1.SchemeGroupVersion.String(),
			Kind:       "ExecCredential",
		},
		Status: &clientauthv1.ExecCredentialStatus{},
	}

	// Tampering for the negative test: a well formed credential holding the
	// wrong key. The request is signed and sent, and the server rejects it,
	// which is what proves the server verifies rather than merely parses.
	tamper := os.Getenv("HTTPSIG_DEMO_TAMPER") != ""

	switch alg := in.Spec.HTTPSignature.Algorithm; alg {
	case "hmac-sha256":
		secret, err := readSecret(filepath.Join(*fixtures, "hmac.secret"))
		if err != nil {
			return err
		}
		if tamper {
			secret = append([]byte("wrong-"), secret...)
		}
		// The root secret, and a stage that carries no From because this is the
		// root. The client folds the whole ladder on every request, taking the
		// date from the signature's own created parameter, so the two sides
		// agree even across a date boundary.
		//
		// The stage is here only because the ladder has a scope step, and every
		// holder has to state a value for one. A ladder of dates and literals
		// alone would need no stage at all.
		//
		// The client tells the plugin the ladder in
		// in.Spec.HTTPSignature.KeyDerivation, and this ignores it: a plugin
		// returning the root has no derivation to do. A broker returning a rung
		// would fold through that ladder and report where it stopped.
		if *cluster == "" {
			return fmt.Errorf("--cluster is required for %s, because the ladder has a cluster scope step", alg)
		}
		out.Status.HTTPSignature = &clientauthv1.HTTPSignatureCredential{
			KeyID:  hmacKeyID,
			Secret: string(secret),
			Stage:  &clientauthv1.HTTPSignatureStage{Scope: map[string]string{"cluster": *cluster}},
		}
	case "ecdsa-p384-sha384":
		pem, err := os.ReadFile(filepath.Join(*fixtures, "ecdsa-p384.key"))
		if err != nil {
			return err
		}
		if tamper {
			// An unrelated key of the same kind, so the request is well formed
			// and only the signature is wrong. Corrupting the PEM would fail in
			// the client before anything reached the server, testing nothing.
			pem, err = os.ReadFile(filepath.Join(*fixtures, "ecdsa-p384.tamper.key"))
			if err != nil {
				return fmt.Errorf("reading the tampering key: %w", err)
			}
		}
		out.Status.HTTPSignature = &clientauthv1.HTTPSignatureCredential{
			KeyID:      ecdsaKeyID,
			PrivateKey: string(pem),
		}
	default:
		return fmt.Errorf("no demo key for algorithm %q", alg)
	}

	return json.NewEncoder(os.Stdout).Encode(out)
}

// readSecret trims the trailing newline an editor or a shell redirect leaves
// behind. A secret differing by one byte fails as a signature mismatch, with
// nothing in the error to suggest why.
func readSecret(path string) ([]byte, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return []byte(strings.TrimRight(string(raw), "\r\n")), nil
}
