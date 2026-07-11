package observatory

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"unicode/utf8"

	"gopkg.in/yaml.v3"
)

type StagedTarget struct {
	Root     string
	Evidence TargetEvidence
}

type targetDescriptor struct {
	Kind          string
	Name          string
	ID            string
	DeclaredTools []string
}

type targetWalkFunc func(rel string, info fs.FileInfo, file *os.File) (descend bool, err error)

var pluginIDPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)
var pluginToolPattern = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_-]{0,63}$`)
var skillIDPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,63}$`)

func StageTarget(target string, destination string, limits LimitsConfig) (StagedTarget, error) {
	return processTarget(target, destination, limits, true)
}

func InspectTarget(target string, limits LimitsConfig) (StagedTarget, error) {
	return processTarget(target, "", limits, false)
}

func processTarget(target string, destination string, limits LimitsConfig, copyTarget bool) (StagedTarget, error) {
	root, expectedRoot, err := targetRootPath(target)
	if err != nil {
		return StagedTarget{}, err
	}
	if copyTarget {
		if err := os.MkdirAll(filepath.Dir(destination), 0o700); err != nil {
			return StagedTarget{}, fmt.Errorf("create staged target parent: %w", err)
		}
		if err := os.Mkdir(destination, 0o700); err != nil {
			return StagedTarget{}, fmt.Errorf("create staged target directory: %w", err)
		}
	}

	type stagedFile struct {
		rel    string
		size   int64
		mode   fs.FileMode
		sha256 []byte
	}
	type stagedDirectory struct {
		rel  string
		mode fs.FileMode
	}

	evidence := TargetEvidence{}
	files := []stagedFile{}
	directories := []stagedDirectory{}
	var skillManifest []byte
	var pluginManifest []byte
	skillManifestFound := false
	pluginManifestFound := false

	err = walkTargetTree(root, limits.MaxFiles, func(rel string, info fs.FileInfo, opened *os.File) (bool, error) {
		if rel == "." && (!os.SameFile(expectedRoot, info) || expectedRoot.Mode() != info.Mode()) {
			return false, fmt.Errorf("target root changed while staging")
		}
		if !utf8.ValidString(rel) {
			return false, fmt.Errorf("target contains a non-UTF-8 path")
		}
		if strings.ContainsAny(rel, "\x00\r\n") {
			return false, fmt.Errorf("target contains an unsupported control character in path %q", rel)
		}
		if hasPathComponent(rel, ".git") {
			omission := TargetOmission{Path: rel, Reason: "excluded Git metadata"}
			if info.Mode().IsRegular() {
				omission.Bytes = info.Size()
			}
			evidence.Omitted = append(evidence.Omitted, omission)
			if len(files)+len(directories)+len(evidence.Omitted) > limits.MaxFiles {
				return false, fmt.Errorf("target exceeds maxFiles entries (%d)", limits.MaxFiles)
			}
			return false, nil
		}
		if hasPathComponent(rel, ".gitattributes") {
			return false, fmt.Errorf("target contains unsupported Git attributes: %s", rel)
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return false, fmt.Errorf("target contains unsupported symlink: %s", rel)
		}
		if info.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 {
			return false, fmt.Errorf("target contains unsupported special permission bits: %s", rel)
		}

		if info.IsDir() {
			directories = append(directories, stagedDirectory{rel: rel, mode: info.Mode()})
			if len(files)+len(directories)+len(evidence.Omitted) > limits.MaxFiles {
				return false, fmt.Errorf("target exceeds maxFiles entries (%d)", limits.MaxFiles)
			}
			if copyTarget && rel != "." {
				destinationDirectory := filepath.Join(destination, filepath.FromSlash(rel))
				if err := os.Mkdir(destinationDirectory, 0o700); err != nil {
					return false, fmt.Errorf("create staged directory %s: %w", rel, err)
				}
			}
			return true, nil
		}

		if !info.Mode().IsRegular() {
			return false, fmt.Errorf("target contains unsupported non-regular file: %s", rel)
		}
		if opened == nil {
			return false, fmt.Errorf("secure walker did not provide an open file for %s", rel)
		}
		if info.Size() > limits.MaxFileBytes {
			return false, fmt.Errorf("target file exceeds maxFileBytes (%d): %s", limits.MaxFileBytes, rel)
		}
		evidence.TotalBytes += info.Size()
		if evidence.TotalBytes > limits.MaxTotalBytes {
			return false, fmt.Errorf("target exceeds maxTotalBytes (%d)", limits.MaxTotalBytes)
		}

		fileHash := sha256.New()
		writers := []io.Writer{fileHash}
		var manifest bytes.Buffer
		isManifest := rel == "SKILL.md" || rel == "openclaw.plugin.json"
		if isManifest {
			if info.Size() > 1<<20 {
				return false, fmt.Errorf("target manifest exceeds 1 MiB: %s", rel)
			}
			writers = append(writers, &manifest)
		}

		var out *os.File
		if copyTarget {
			dest := filepath.Join(destination, filepath.FromSlash(rel))
			out, err = os.OpenFile(dest, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
			if err != nil {
				return false, fmt.Errorf("create staged file %s: %w", rel, err)
			}
			writers = append(writers, out)
		}

		copied, copyErr := io.Copy(io.MultiWriter(writers...), io.LimitReader(opened, info.Size()+1))
		postInfo, statErr := opened.Stat()
		var closeOutErr error
		if out != nil {
			closeOutErr = out.Close()
		}
		if copyErr != nil {
			return false, fmt.Errorf("copy target file %s: %w", rel, copyErr)
		}
		if copied != info.Size() || statErr != nil || !sameTargetFileSnapshot(info, postInfo) {
			return false, fmt.Errorf("target file changed while staging: %s", rel)
		}
		if closeOutErr != nil {
			return false, fmt.Errorf("close staged file %s: %w", rel, closeOutErr)
		}

		files = append(files, stagedFile{rel: rel, size: info.Size(), mode: info.Mode(), sha256: fileHash.Sum(nil)})
		if len(files)+len(directories)+len(evidence.Omitted) > limits.MaxFiles {
			return false, fmt.Errorf("target exceeds maxFiles entries (%d)", limits.MaxFiles)
		}
		if rel == "SKILL.md" {
			skillManifest = append([]byte(nil), manifest.Bytes()...)
			skillManifestFound = true
		}
		if rel == "openclaw.plugin.json" {
			pluginManifest = append([]byte(nil), manifest.Bytes()...)
			pluginManifestFound = true
		}
		return false, nil
	})
	if err != nil {
		return StagedTarget{}, fmt.Errorf("stage target: %w", err)
	}
	if len(files) == 0 {
		return StagedTarget{}, fmt.Errorf("target contains no regular files: %s", target)
	}

	descriptor, err := descriptorFromManifests(root, skillManifest, skillManifestFound, pluginManifest, pluginManifestFound)
	if err != nil {
		return StagedTarget{}, err
	}
	evidence.Name = descriptor.Name
	evidence.Kind = descriptor.Kind
	evidence.ID = descriptor.ID
	evidence.DeclaredTools = descriptor.DeclaredTools

	sort.Slice(files, func(i, j int) bool { return files[i].rel < files[j].rel })
	sort.Slice(directories, func(i, j int) bool { return directories[i].rel < directories[j].rel })
	sort.Slice(evidence.Omitted, func(i, j int) bool { return evidence.Omitted[i].Path < evidence.Omitted[j].Path })
	hash := sha256.New()
	if err := writeDigestField(hash, []byte("observatory.target.v3")); err != nil {
		return StagedTarget{}, err
	}
	for _, omission := range evidence.Omitted {
		for _, field := range []string{"omitted", omission.Path, omission.Reason, fmt.Sprintf("%d", omission.Bytes)} {
			if err := writeDigestField(hash, []byte(field)); err != nil {
				return StagedTarget{}, err
			}
		}
	}
	for _, directory := range directories {
		mode := fmt.Sprintf("%04o", directory.mode.Perm())
		for _, field := range []string{"directory", directory.rel, mode} {
			if err := writeDigestField(hash, []byte(field)); err != nil {
				return StagedTarget{}, err
			}
		}
		evidence.Directories = append(evidence.Directories, TargetDirectory{Path: directory.rel, Mode: mode})
	}
	for _, file := range files {
		for _, field := range [][]byte{
			[]byte("file"),
			[]byte(file.rel),
			[]byte(fmt.Sprintf("%04o", file.mode.Perm())),
			file.sha256,
		} {
			if err := writeDigestField(hash, field); err != nil {
				return StagedTarget{}, err
			}
		}
		evidence.Files = append(evidence.Files, TargetFile{Path: file.rel, Bytes: file.size, Mode: fmt.Sprintf("%04o", file.mode.Perm())})
	}
	evidence.FileCount = len(evidence.Files)
	evidence.DirectoryCount = len(evidence.Directories)
	evidence.SHA256 = "sha256:" + hex.EncodeToString(hash.Sum(nil))
	stagedRoot := destination
	if !copyTarget {
		stagedRoot = root
	}
	return StagedTarget{Root: stagedRoot, Evidence: evidence}, nil
}

func hasPathComponent(path string, component string) bool {
	for _, part := range strings.Split(path, "/") {
		if strings.EqualFold(part, component) {
			return true
		}
	}
	return false
}

func writeDigestField(writer io.Writer, value []byte) error {
	if err := binary.Write(writer, binary.BigEndian, uint64(len(value))); err != nil {
		return err
	}
	_, err := writer.Write(value)
	return err
}

func targetRootPath(target string) (string, fs.FileInfo, error) {
	target = strings.TrimSpace(target)
	if target == "" {
		return "", nil, fmt.Errorf("behavior target is required")
	}
	abs, err := filepath.Abs(target)
	if err != nil {
		return "", nil, err
	}
	info, err := os.Lstat(abs)
	if err != nil {
		return "", nil, fmt.Errorf("inspect behavior target: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return "", nil, fmt.Errorf("behavior target cannot be a symlink: %s", target)
	}
	root := abs
	if !info.IsDir() {
		base := filepath.Base(abs)
		if !info.Mode().IsRegular() || (base != "SKILL.md" && base != "openclaw.plugin.json") {
			return "", nil, fmt.Errorf("behavior target must be a skill/plugin directory or its manifest: %s", target)
		}
		root = filepath.Dir(abs)
	}
	rootInfo, err := os.Lstat(root)
	if err != nil {
		return "", nil, fmt.Errorf("inspect behavior target root: %w", err)
	}
	if !rootInfo.IsDir() || rootInfo.Mode()&os.ModeSymlink != 0 {
		return "", nil, fmt.Errorf("behavior target root must be a regular non-symlink directory: %s", target)
	}
	return root, rootInfo, nil
}

func descriptorFromManifests(root string, skill []byte, skillFound bool, plugin []byte, pluginFound bool) (targetDescriptor, error) {
	if skillFound && pluginFound {
		return targetDescriptor{}, fmt.Errorf("behavior target is ambiguous (both skill and plugin manifests): %s", root)
	}
	if skillFound {
		name, present, err := parseSkillFrontmatterName(skill)
		if err != nil {
			return targetDescriptor{}, err
		}
		if !present {
			return targetDescriptor{Kind: "skill", Name: "Unnamed skill", ID: "observed"}, nil
		}
		if !skillIDPattern.MatchString(name) {
			return targetDescriptor{}, fmt.Errorf("skill manifest has invalid canonical name %q", name)
		}
		return targetDescriptor{Kind: "skill", Name: name, ID: name}, nil
	}
	if !pluginFound {
		return targetDescriptor{}, fmt.Errorf("behavior target is missing a regular SKILL.md or openclaw.plugin.json: %s", root)
	}

	var manifest struct {
		ID        string `json:"id"`
		Name      string `json:"name"`
		Contracts struct {
			Tools []string `json:"tools"`
		} `json:"contracts"`
	}
	if err := json.Unmarshal(plugin, &manifest); err != nil {
		return targetDescriptor{}, fmt.Errorf("parse plugin manifest: %w", err)
	}
	manifest.ID = strings.TrimSpace(manifest.ID)
	manifest.Name = strings.TrimSpace(manifest.Name)
	if !pluginIDPattern.MatchString(manifest.ID) {
		return targetDescriptor{}, fmt.Errorf("plugin manifest has invalid id %q", manifest.ID)
	}
	if manifest.Name == "" {
		manifest.Name = manifest.ID
	}
	if len(manifest.Name) > 120 || strings.ContainsAny(manifest.Name, "\x00\r\n") {
		return targetDescriptor{}, fmt.Errorf("plugin manifest has invalid name")
	}
	seenTools := map[string]bool{}
	tools := make([]string, 0, len(manifest.Contracts.Tools))
	for _, tool := range manifest.Contracts.Tools {
		if !pluginToolPattern.MatchString(tool) {
			return targetDescriptor{}, fmt.Errorf("plugin manifest has invalid declared tool %q", tool)
		}
		if !seenTools[tool] {
			seenTools[tool] = true
			tools = append(tools, tool)
		}
	}
	sort.Strings(tools)
	return targetDescriptor{Kind: "plugin", Name: manifest.Name, ID: manifest.ID, DeclaredTools: tools}, nil
}

func readSkillName(manifest []byte) string {
	name, present, err := parseSkillFrontmatterName(manifest)
	if err != nil || !present || len(name) > 120 || strings.ContainsAny(name, "\x00\r\n") {
		return "Unnamed skill"
	}
	return name
}

func parseSkillFrontmatterName(manifest []byte) (string, bool, error) {
	const maxSkillManifestBytes = 1 << 20
	if len(manifest) > maxSkillManifestBytes {
		return "", false, fmt.Errorf("skill manifest exceeds 1 MiB")
	}
	scanner := bufio.NewScanner(bytes.NewReader(manifest))
	scanner.Buffer(make([]byte, 64<<10), maxSkillManifestBytes+1)
	if !scanner.Scan() {
		if err := scanner.Err(); err != nil {
			return "", false, fmt.Errorf("read skill manifest frontmatter: %w", err)
		}
		return "", false, nil
	}
	opening := strings.TrimPrefix(scanner.Text(), "\ufeff")
	if opening != "---" {
		return "", false, nil
	}
	var frontmatter bytes.Buffer
	for scanner.Scan() {
		rawLine := scanner.Text()
		if rawLine == "---" {
			var document yaml.Node
			if err := yaml.Unmarshal(frontmatter.Bytes(), &document); err != nil {
				return "", false, fmt.Errorf("parse skill manifest frontmatter: %w", err)
			}
			if len(document.Content) == 0 {
				return "", false, nil
			}
			mapping := document.Content[0]
			if mapping.Kind != yaml.MappingNode {
				return "", false, fmt.Errorf("skill manifest frontmatter must be a mapping")
			}
			name := ""
			found := false
			for index := 0; index+1 < len(mapping.Content); index += 2 {
				key, value := mapping.Content[index], mapping.Content[index+1]
				if key.Value != "name" {
					continue
				}
				if found {
					return "", false, fmt.Errorf("skill manifest contains duplicate name fields")
				}
				found = true
				if value.Kind != yaml.ScalarNode || value.Tag != "!!str" {
					return "", false, fmt.Errorf("skill manifest name must be a string")
				}
				name = value.Value
			}
			return name, found, nil
		}
		frontmatter.WriteString(rawLine)
		frontmatter.WriteByte('\n')
	}
	if err := scanner.Err(); err != nil {
		return "", false, fmt.Errorf("read skill manifest frontmatter: %w", err)
	}
	return "", false, fmt.Errorf("skill manifest has unterminated frontmatter")
}
