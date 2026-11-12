package store

import "strings"

// RepoRelativePath strips a local checkout prefix from a stored workflow
// path. API-mode scans store ".github/workflows/ci.yml", while older
// clone-mode scans stored "<keep-dir>/<owner>/<repo>/.github/...".
// Comparing or deduplicating findings across scan modes must normalize
// first, or the same finding looks like two.
func RepoRelativePath(owner, repo, path string) string {
	path = strings.ReplaceAll(path, "\\", "/")
	seg := owner + "/" + repo + "/"
	if strings.HasPrefix(path, seg) {
		return path[len(seg):]
	}
	if idx := strings.LastIndex(path, "/"+seg); idx >= 0 {
		return path[idx+len(seg)+1:]
	}
	return path
}
