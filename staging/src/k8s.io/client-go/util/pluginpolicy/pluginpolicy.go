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

// Package pluginpolicy decides whether client-go may execute a program that
// supplies credentials.
//
// The policy is set outside the file it governs: an allowlist stored in the same
// kubeconfig that names the program would be worth nothing, since whoever can
// edit the command can edit the allowlist. In kubectl it comes from the user's
// preferences file and is stamped onto the client configuration.
//
// This package holds the decision in one place because more than one kind of
// credential program exists: the exec credential plugin, and the command that
// supplies an HTTP message signature credential. Both run a program chosen by
// configuration, with the client's privileges, so both answer to the same policy.
// Two copies of a security control drift, and the copy that drifts is the one
// nobody is looking at.
//
// It deliberately depends on nothing but the standard library, so anything that
// runs a credential program can use it.
package pluginpolicy

import (
	"fmt"
	"os/exec"
	"path/filepath"
	"sync"
)

// Type is the policy governing which credential programs may run.
type Type string

const (
	// AllowAll permits any program. The empty policy means this, because
	// policies were introduced after credential programs were.
	AllowAll Type = "AllowAll"
	// DenyAll permits none.
	DenyAll Type = "DenyAll"
	// Allowlist permits only the programs named in the allowlist.
	Allowlist Type = "Allowlist"
)

// Validate reports whether a policy and its allowlist agree. A misspelled
// allowlist field would otherwise leave a policy that names no program, which
// silently permits everything, so a policy that does not make sense is an error
// rather than a default.
// A nil allowlist means unspecified, which is not the same as an empty one.
func Validate(policyType Type, allowlist []string) error {
	switch policyType {
	case "", AllowAll, DenyAll:
		if allowlist != nil {
			return fmt.Errorf("misconfigured credential plugin allowlist: plugin policy is %q but allowlist is non-nil", policyType)
		}
		return nil
	case Allowlist:
		// An unspecified allowlist is what a misspelled field name produces.
		// Because this is a security knob, that fails immediately rather than
		// proceeding with a policy that names nothing.
		if allowlist == nil {
			return fmt.Errorf("credential plugin policy set to %q, but allowlist is unspecified", Allowlist)
		}
		if len(allowlist) == 0 {
			return fmt.Errorf("credential plugin policy set to %q, but allowlist is empty; use %q policy instead", Allowlist, DenyAll)
		}
		for i, entry := range allowlist {
			if entry == "" {
				return fmt.Errorf("misconfigured credential plugin allowlist: empty allowlist entry #%d", i+1)
			}
			// A path that is not already normalized would compare unequal to
			// the same program written normally, so the mismatch is reported
			// rather than silently cleaned.
			if cleaned := filepath.Clean(entry); cleaned != entry {
				return fmt.Errorf("non-normalized file path: %q vs %q", entry, cleaned)
			}
		}
		return nil
	default:
		return fmt.Errorf("unknown plugin policy: %q", policyType)
	}
}

// A Checker decides whether one configured command may run. It is safe for
// concurrent use, and caches the path resolutions it performs, because a check
// happens whenever a credential is refreshed rather than once.
type Checker struct {
	policyType Type
	// configured is the command as written in configuration, cleaned so that it
	// compares against an allowlist entry the same way every time.
	configured string
	entries    []string

	mu sync.Mutex
	// resolved holds allowlist entries and command paths already found to
	// match, including the results of path resolution.
	resolved map[string]bool
}

// New returns a Checker for a command under a policy. The policy is validated
// here, so a misconfigured one fails when the client is built rather than when a
// credential is first needed.
func New(command string, policyType Type, allowlist []string) (*Checker, error) {
	if err := Validate(policyType, allowlist); err != nil {
		return nil, err
	}
	c := &Checker{
		policyType: policyType,
		configured: filepath.Clean(command),
		entries:    allowlist,
		resolved:   map[string]bool{},
	}
	for _, entry := range allowlist {
		if entry != "" {
			c.resolved[entry] = true
		}
	}
	return c, nil
}

// Check reports whether cmd may run. When the policy is an allowlist and the
// command matches only after path resolution, cmd.Path is updated to the
// resolved path, so the program that was checked is the program that runs.
func (c *Checker) Check(cmd *exec.Cmd) error {
	switch c.policyType {
	case "", AllowAll:
		return nil
	case DenyAll:
		return fmt.Errorf("plugin %q not allowed: policy set to %q", c.configured, DenyAll)
	case Allowlist:
		return c.checkAllowlist(cmd)
	default:
		return fmt.Errorf("unknown plugin policy %q", c.policyType)
	}
}

func (c *Checker) checkAllowlist(cmd *exec.Cmd) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	// An exact match on either the configured command or the path already
	// resolved by exec.Command needs no further work.
	if c.resolved[c.configured] || c.resolved[cmd.Path] {
		return nil
	}

	var resolvedPath string
	var resolveErr error
	if cmd.Path != c.configured {
		// exec.Command already resolved it; reuse that result rather than
		// resolving twice and possibly differently.
		resolvedPath, resolveErr = cmd.Path, cmd.Err
	} else {
		resolvedPath, resolveErr = exec.LookPath(cmd.Path)
		if resolvedPath != "" {
			// Run only the path that was checked.
			cmd.Path = resolvedPath
		}
	}
	if resolveErr != nil {
		return fmt.Errorf("plugin path %q cannot be resolved for credential plugin allowlist check: %w", cmd.Path, resolveErr)
	}
	if c.resolved[resolvedPath] {
		return nil
	}

	// No verbatim match, so resolve the allowlist entries too: an entry written
	// as a bare name and a command written as a path can be the same program.
	c.resolveEntriesLocked()
	if c.resolved[resolvedPath] {
		return nil
	}
	return fmt.Errorf("plugin path %q is not permitted by the credential plugin allowlist", cmd.Path)
}

// resolveEntriesLocked adds the resolved form of each allowlist entry to the
// match set. Entries that cannot be resolved are skipped: an allowlist may name
// programs that are not installed, and that is not an error for the program that
// is being checked now.
func (c *Checker) resolveEntriesLocked() {
	for _, entry := range c.entries {
		if entry == "" {
			continue
		}
		resolved, err := exec.LookPath(entry)
		if err != nil || resolved == "" {
			continue
		}
		c.resolved[resolved] = true
	}
}
