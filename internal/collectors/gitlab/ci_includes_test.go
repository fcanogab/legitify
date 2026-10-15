package gitlab

import "testing"

// TestParseCIIncludes_Shapes covers every shape `include:` can legally take in a
// .gitlab-ci.yml file. In particular, the sequence and bare-scalar cases are
// regression tests for a bug where decoding into a `*yaml.Node` struct field (instead
// of a plain `yaml.Node`) made gopkg.in/yaml.v3 fail with "cannot unmarshal !!seq into
// yaml.Node" for list-style includes - by far the most common real-world form - and
// silently produced an empty, useless node for mapping-style includes.
func TestParseCIIncludes_Shapes(t *testing.T) {
	tests := []struct {
		name          string
		yaml          string
		wantLocals    []string
		wantExternals []externalCIInclude
		wantErr       bool
	}{
		{
			name:       "no include key",
			yaml:       "stages:\n  - build\n",
			wantLocals: nil,
		},
		{
			name:       "bare scalar local include",
			yaml:       "include: '/ci/build.yml'\n",
			wantLocals: []string{"/ci/build.yml"},
		},
		{
			name:       "single mapping local include",
			yaml:       "include:\n  local: '/ci/build.yml'\n",
			wantLocals: []string{"/ci/build.yml"},
		},
		{
			name: "sequence of mapping includes (most common real-world form)",
			yaml: "stages:\n  - build\n" +
				"include:\n" +
				"  - local: '/ci/build.yml'\n" +
				"  - project: 'foo/bar'\n" +
				"    ref: main\n",
			wantLocals: []string{"/ci/build.yml"},
			wantExternals: []externalCIInclude{
				{kind: "project", reference: "foo/bar@main", pinned: false},
			},
		},
		{
			name: "sequence with pinned project ref",
			yaml: "include:\n" +
				"  - project: 'foo/bar'\n" +
				"    ref: " + "0123456789abcdef0123456789abcdef01234567" + "\n",
			wantExternals: []externalCIInclude{
				{kind: "project", reference: "foo/bar@0123456789abcdef0123456789abcdef01234567", pinned: true},
			},
		},
		{
			name: "remote include is never pinned",
			yaml: "include:\n" +
				"  - remote: 'https://example.com/ci.yml'\n",
			wantExternals: []externalCIInclude{
				{kind: "remote", reference: "https://example.com/ci.yml", pinned: false},
			},
		},
		{
			name: "pinned vs unpinned component",
			yaml: "include:\n" +
				"  - component: 'gitlab.com/my-org/my-component@1.0.0'\n" +
				"  - component: 'gitlab.com/my-org/my-component@" + "0123456789abcdef0123456789abcdef01234567" + "'\n",
			wantExternals: []externalCIInclude{
				{kind: "component", reference: "gitlab.com/my-org/my-component@1.0.0", pinned: false},
				{kind: "component", reference: "gitlab.com/my-org/my-component@0123456789abcdef0123456789abcdef01234567", pinned: true},
			},
		},
		{
			name: "template include is ignored",
			yaml: "include:\n" +
				"  - template: 'Security/SAST.gitlab-ci.yml'\n",
			wantLocals:    nil,
			wantExternals: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			locals, externals, err := parseCIIncludes([]byte(tt.yaml))
			if (err != nil) != tt.wantErr {
				t.Fatalf("parseCIIncludes() error = %v, wantErr %v", err, tt.wantErr)
			}
			if err != nil {
				return
			}

			var gotLocals []string
			for _, l := range locals {
				gotLocals = append(gotLocals, l.path)
			}
			if !stringSlicesEqual(gotLocals, tt.wantLocals) {
				t.Errorf("locals = %v, want %v", gotLocals, tt.wantLocals)
			}

			if !externalSlicesEqual(externals, tt.wantExternals) {
				t.Errorf("externals = %+v, want %+v", externals, tt.wantExternals)
			}
		})
	}
}

func stringSlicesEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func externalSlicesEqual(a, b []externalCIInclude) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
