package proxmox

import (
	"os"
	"strings"
	"testing"
)

func TestTemplateBuilderExpandsRootBeforeProvisioning(t *testing.T) {
	script, err := os.ReadFile("build-observatory-template.sh")
	if err != nil {
		t.Fatal(err)
	}
	text := string(script)
	convert := strings.Index(text, `qemu-img convert -O qcow2 "$source_image" "$custom_image"`)
	growImage := strings.Index(text, `qemu-img resize "$custom_image" "$disk_size"`)
	expandGPT := strings.Index(text, `part-expand-gpt /dev/sda`)
	expandRoot := strings.Index(text, `part-resize /dev/sda 1 -34`)
	provision := strings.Index(text, "virt-customize -a \"$custom_image\"")
	if convert < 0 || growImage <= convert || expandGPT <= growImage || expandRoot <= expandGPT || provision <= expandRoot {
		t.Fatal("template root filesystem is not expanded before guest provisioning")
	}
	if strings.Contains(text, "\nvirt-resize ") {
		t.Fatal("template builder must preserve the source image's non-sequential partition numbers")
	}
	if strings.Contains(text, `qm resize "$template_id" scsi0 "$disk_size"`) {
		t.Fatal("template builder still relies on a post-provision disk resize")
	}
}

func TestTemplateProvisionerIncludesLocalRuntimePath(t *testing.T) {
	script, err := os.ReadFile("provision-observatory-guest.sh")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(script), "export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin") {
		t.Fatal("template provisioner does not expose pinned /usr/local runtimes during libguestfs execution")
	}
}

func TestTemplateBuilderLeavesClonesBootableAndDisposable(t *testing.T) {
	script, err := os.ReadFile("build-observatory-template.sh")
	if err != nil {
		t.Fatal(err)
	}
	text := string(script)
	if !strings.Contains(text, `printf "uninitialized\n" > /etc/machine-id`) {
		t.Fatal("template builder does not leave a first-boot machine ID seed")
	}
	if !strings.Contains(text, `--ciupgrade 0`) {
		t.Fatal("template builder allows cloud-init to attempt an offline package upgrade")
	}
	if strings.Contains(text, `qm set "$template_id" --protection 1`) {
		t.Fatal("template protection is inherited by clones and prevents Crabbox cleanup")
	}
}

func TestTemplateProvisionerImportsRuntimeThroughContainerd(t *testing.T) {
	script, err := os.ReadFile("provision-observatory-guest.sh")
	if err != nil {
		t.Fatal(err)
	}
	text := string(script)
	if !strings.Contains(text, `ctr --namespace moby images import --base-name observatory "$archive"`) ||
		!strings.Contains(text, `ctr --namespace moby images tag --force "$import_ref" "$image"`) {
		t.Fatal("runtime loader does not import and tag the pinned OCI archive through Docker's containerd namespace")
	}
	if strings.Contains(text, `docker-daemon:${image}`) {
		t.Fatal("runtime loader still relies on Skopeo's Docker API client")
	}
	if strings.Contains(text, `docker image inspect "$image" --format '{{.Id}}'`) {
		t.Fatal("runtime loader relies on Docker's backend-specific image ID semantics")
	}
}

func TestTemplateValidatorDeniesEphemeralListeners(t *testing.T) {
	script, err := os.ReadFile("validate-observatory-template.sh")
	if err != nil {
		t.Fatal(err)
	}
	text := string(script)
	if !strings.Contains(text, `SystemCallFilter=~bind listen accept accept4 io_uring_setup io_uring_register io_uring_enter`) {
		t.Fatal("template validator does not exercise the hostile lane listener syscall denial")
	}
	if strings.Contains(text, `SocketBindAllow=ipv4:tcp:65535`) {
		t.Fatal("template validator still grants an unrelated listener port")
	}
}

func TestGatedPipelineAvoidsCrabboxDefaultTargetExclusion(t *testing.T) {
	controller, err := os.ReadFile("run-gated-observatory.sh")
	if err != nil {
		t.Fatal(err)
	}
	runner, err := os.ReadFile("run-security-gate-crabbox.sh")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(controller), `"$stage/target"`) ||
		strings.Contains(string(runner), `"$repo_root/target"`) {
		t.Fatal("Crabbox excludes a top-level target directory from workspace sync")
	}
	if !strings.Contains(string(controller), `"$stage/artifact"`) ||
		!strings.Contains(string(runner), `"$repo_root/artifact"`) {
		t.Fatal("controller and runner do not agree on the staged artifact path")
	}
}

func TestGatedPipelineReturnsBehaviorGrade(t *testing.T) {
	script, err := os.ReadFile("run-gated-observatory.sh")
	if err != nil {
		t.Fatal(err)
	}
	text := string(script)
	if !strings.Contains(text, `--grade-output "$output_root/behavior-grade.json"`) ||
		!strings.Contains(text, `--slurpfile behaviorGrade "$output_root/behavior-grade.json"`) ||
		!strings.Contains(text, `behaviorGrade: $behaviorGrade[0]`) {
		t.Fatal("gated pipeline does not return the deterministic behavior grade")
	}
}
