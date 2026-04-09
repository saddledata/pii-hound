package git

import (
	"os/exec"
	"strings"
)

// GetChangedFiles returns a list of files that have changed in the git repository.
// It includes staged, unstaged, and optionally compares against a base ref.
func GetChangedFiles(base string) ([]string, error) {
	var files []string
	seen := make(map[string]bool)

	addFiles := func(output string) {
		lines := strings.Split(output, "\n")
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if line != "" && !seen[line] {
				files = append(files, line)
				seen[line] = true
			}
		}
	}

	// 1. Get changed files compared to base if provided
	if base != "" {
		out, err := exec.Command("git", "diff", "--name-only", base+"...HEAD").Output()
		if err == nil {
			addFiles(string(out))
		} else {
			// Fallback to simple diff if range diff fails
			out, err = exec.Command("git", "diff", "--name-only", base).Output()
			if err == nil {
				addFiles(string(out))
			}
		}
	}

	// 2. Get staged changes
	out, err := exec.Command("git", "diff", "--name-only", "--cached").Output()
	if err == nil {
		addFiles(string(out))
	}

	// 3. Get unstaged changes
	out, err = exec.Command("git", "diff", "--name-only").Output()
	if err == nil {
		addFiles(string(out))
	}

	// 4. Get untracked files
	out, err = exec.Command("git", "ls-files", "--others", "--exclude-standard").Output()
	if err == nil {
		addFiles(string(out))
	}

	return files, nil
}

// IsGitRepo checks if the current directory is inside a git repository
func IsGitRepo() bool {
	err := exec.Command("git", "rev-parse", "--is-inside-work-tree").Run()
	return err == nil
}
