package store

import "testing"

func TestRepoRelativePath(t *testing.T) {
	for _, tc := range []struct{ path, want string }{
		{".github/workflows/ci.yml", ".github/workflows/ci.yml"},
		{"clones/acme/app/.github/workflows/ci.yml", ".github/workflows/ci.yml"},
		{"/tmp/fluxgate-123/acme/app/.gitlab-ci.yml", ".gitlab-ci.yml"},
		{"acme/app/Jenkinsfile", "Jenkinsfile"},
		{"/home/acme/app/clones/acme/app/.tekton/build.yaml", ".tekton/build.yaml"},
		{"other/app/.github/workflows/ci.yml", "other/app/.github/workflows/ci.yml"},
	} {
		if got := RepoRelativePath("acme", "app", tc.path); got != tc.want {
			t.Errorf("RepoRelativePath(%q) = %q, want %q", tc.path, got, tc.want)
		}
	}
}
