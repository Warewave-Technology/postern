//go:build integration

package integration

/*
 * §9.3.1 — Ansible role hardening: test that the postern_target role
 * enforces correct file modes and ownership on Alpine sshd.
 *
 * What it tests:
 *   1. Starts a real Alpine sshd container (postern-certtarget:test).
 *   2. Installs ansible inside the container, copies the playbook into it,
 *      and runs ansible-playbook against it (apply, not dry-run).
 *   3. Verifies mode and ownership of:
 *        - /etc/sudoers.d/postern          → 0440 root:root
 *        - /etc/ssh/auth_principals/       → 0755 root:root (dizin: x biti şart)
 *        - /etc/ssh/auth_principals/*      → 0644 root:root
 *        - sshd -T -C user=postern,host=localhost shows correct APF
 *
 * Mutation: mode 0440 → 0644 in the gruba causes this test to FAIL.
 */

import (
	"context"
	"io"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

const ansibleGroupImage = "postern-certtarget:test"

// ansibleTarget is an Alpine sshd container with ansible installed and the
// playbook copied in.
type ansibleTarget struct {
	cont testcontainers.Container
}

// startAnsibleTarget starts the container and installs ansible inside it.
func startAnsibleTarget(t *testing.T) ansibleTarget {
	t.Helper()
	ctx := context.Background()

	cont, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: testcontainers.ContainerRequest{
			Image:        ansibleGroupImage,
			ExposedPorts: []string{"22/tcp"},
			Files: []testcontainers.ContainerFile{{
				Reader:            strings.NewReader(""),
				ContainerFilePath: "/etc/ssh/postern_ca.pub",
				FileMode:          0o644,
			}},
			WaitingFor: wait.ForListeningPort("22/tcp").WithStartupTimeout(3 * time.Minute),
		},
		Started: true,
	})
	if err != nil {
		t.Fatalf("ansible hedefi başlatılamadı: %v\n\n"+
			"%s imajı yoksa önce `make test-images` çalıştır.",
			err, ansibleGroupImage)
	}

	// Install ansible inside the running container.
	// bash is needed because the Ansible role's tasks use executable: /bin/bash.
	installScript := `set -e
apk add --no-cache ansible openssl bash
mkdir -p /etc/ansible /root/.ansible/tmp
# Placeholder CA key so ansible doesn't error on unknown host key.
echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC5O==' > /etc/ssh/postern_ca.pub
`
	code, outRd, err := cont.Exec(ctx, []string{"sh", "-c", installScript})
	if err != nil || code != 0 {
		out, _ := io.ReadAll(outRd)
		t.Fatalf("ansible kurma başarısız: exit %d, err=%v output=%s", code, err, string(out))
	}

	t.Cleanup(func() { _ = cont.Terminate(context.Background()) })

	t.Cleanup(func() {
		if !t.Failed() {
			return
		}
		rc, err := cont.Logs(context.Background())
		if err != nil {
			return
		}
		defer rc.Close()
		logOut, _ := io.ReadAll(rc)
		t.Logf("--- hedef sshd log ---\n%s", logOut)
	})

	return ansibleTarget{cont: cont}
}

// copyPlaybook copies the ansible playbook directory into the running container
// using CopyDirToContainer.
func (a ansibleTarget) copyPlaybook(ctx context.Context, t *testing.T) {
	t.Helper()

	// Locate the deploy/ansible directory relative to the repo root.
	// test/integration is at repo-root/test/integration.
	repoRoot := filepath.Join("..", "..")
	ansibleDir := filepath.Join(repoRoot, "deploy", "ansible")

	// Copy the ansible directory into the container.
	if err := a.cont.CopyDirToContainer(ctx, ansibleDir, "/ansible", 0o644); err != nil {
		t.Fatalf("playbook container'a kopyalanamadı: %v", err)
	}

	t.Log("playbook kopyalandı")
}

// statPath returns (mode, owner) for a path inside the container.
func (a ansibleTarget) statPath(ctx context.Context, t *testing.T, path string) (mode, owner string) {
	t.Helper()
	code, outRd, err := a.cont.Exec(ctx, []string{"stat", "-c", "%a %U:%G", path})
	if err != nil {
		t.Fatalf("stat %s exec hata: %v", path, err)
	}
	out, _ := io.ReadAll(outRd)
	if code != 0 {
		t.Fatalf("stat %s başarısız: exit %d, out=%q", path, code, string(out))
	}
	raw := string(out)
	// Docker exec prepends an 8-byte header to each line: stream type (1 byte)
	// + 3 reserved bytes + content length (4 bytes, big-endian uint32).
	// We only need to strip the header from the first line.
	lines := strings.SplitAfterN(raw, "\n", 2)
	var dataLine string
	if len(lines) >= 2 {
		dataLine = lines[0]
	} else {
		dataLine = raw
	}
	// Strip 8-byte Docker exec header if present.
	if len(dataLine) >= 8 {
		dataLine = dataLine[8:]
	}
	// Also strip any remaining ANSI escape sequences.
	// Strip any ANSI escape sequences that may appear.
	dataLine = strings.ReplaceAll(dataLine, "\x1b[0m", "")
	dataLine = strings.ReplaceAll(dataLine, "\x1b[1;32m", "")
	trimmed := strings.TrimSpace(dataLine)
	parts := strings.SplitN(trimmed, " ", 2)
	if len(parts) != 2 {
		t.Fatalf("stat -c çıktısı beklenmedik: raw=%q trimmed=%q", raw, trimmed)
	}
	return parts[0], parts[1]
}

// execShell runs a shell command in the container and returns stdout.
// Does NOT call t.Fatalf on non-zero exit (caller handles exit code).
func (a ansibleTarget) execShell(ctx context.Context, t *testing.T, script string) string {
	t.Helper()
	_, outRd, err := a.cont.Exec(ctx, []string{"sh", "-c", script})
	if err != nil {
		t.Fatalf("exec hata: %v", err)
	}
	out, _ := io.ReadAll(outRd)
	return string(out)
}

// execShellWithRC runs a shell command and returns (stdout, exitCode).
func (a ansibleTarget) execShellWithRC(ctx context.Context, t *testing.T, script string) (string, int) {
	t.Helper()
	code, outRd, err := a.cont.Exec(ctx, []string{"sh", "-c", script})
	out, _ := io.ReadAll(outRd)
	if err != nil {
		t.Fatalf("exec hata: %v", err)
	}
	return string(out), code
}

// TestAnsibleGroupHardening applies the postern_target Ansible role to an
// Alpine sshd container and asserts correct file modes and ownership.
func TestAnsibleGroupHardening(t *testing.T) {
	if testing.Short() {
		t.Skip("short mode: ansible role test skipped")
	}

	defer func() {
		if r := recover(); r != nil {
			t.Logf("PANIC: %v", r)
			panic(r)
		}
	}()

	tgt := startAnsibleTarget(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	// Copy the playbook into the container.
	tgt.copyPlaybook(ctx, t)

	// Run ansible-playbook apply inside the container.
	playbookScript := `
set -e
cd /ansible

# Create a minimal inventory pointing at localhost.
cat > /tmp/inventory.ini << 'EOF'
[postern]
localhost ansible_connection=local
EOF

# Write variables to a YAML file so ansible parses dicts correctly.
cat > /tmp/vars.yml << 'VARSEOF'
postern_ca_pubkey: ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIL+qm5m9qZ5xH7vJGvJGvJGvJGvJGvJGvJGvJGvJGvJG
postern_manage_host: true
postern_principals:
  deploy:
    - deploy
postern_manage_user: postern
postern_manage_principal: postern-manage
postern_manage_shell: /bin/sh
postern_manage_home: /var/lib/postern-managed
postern_manage_sudoers: /etc/sudoers.d/postern
postern_ca_path: /etc/ssh/postern_ca.pub
postern_principals_dir: /etc/ssh/auth_principals
postern_sshd_config: /etc/ssh/sshd_config.d/50-postern.conf
# Bu konteynerde servis yoneticisi yok; sshd'yi test kendisi baslatiyor.
# Rolun reload handler'i uretimde acik ve gurultulu kaliyor.
postern_reload_sshd: false
VARSEOF

# Run ansible-playbook (apply, not check/dry-run).
ansible-playbook \
  -i /tmp/inventory.ini \
  site.yml \
  -e @/tmp/vars.yml \
  2>&1
`
	out, rc := tgt.execShellWithRC(ctx, t, playbookScript)
	t.Logf("ansible-playbook çıktısı (rc=%d):\n%s", rc, out)
	if rc != 0 {
		t.Fatalf("ansible-playbook başarısız: exit %d", rc)
	}

	// ── Verify file modes and ownership ────────────────────────────────

	t.Log("dosya mod ve sahiplik doğrulaması...")

	// /etc/sudoers.d/postern — mode 0440, owner root:root
	mode, owner := tgt.statPath(ctx, t, "/etc/sudoers.d/postern")
	if mode != "440" {
		t.Errorf("/etc/sudoers.d/postern: mode %s, want 440", mode)
	}
	if owner != "root:root" {
		t.Errorf("/etc/sudoers.d/postern: owner %s, want root:root", owner)
	}

	/*
	 * ⚠️ DİZİN 0755, 0644 DEĞİL. Bir dizinden x bitini almak onu
	 * gezilemez yapar; sshd kök olduğu için pratikte okumaya devam eder
	 * (CAP_DAC_OVERRIDE) ve arıza ancak kök olmayan bir okuyucuda
	 * görünür. Rol dizini 0755 açıyor, bu satır onu çiviliyor.
	 */
	dirMode, dirOwner := tgt.statPath(ctx, t, "/etc/ssh/auth_principals")
	if dirMode != "755" {
		t.Errorf("/etc/ssh/auth_principals: dir mode %s, want 755", dirMode)
	}
	if dirOwner != "root:root" {
		t.Errorf("/etc/ssh/auth_principals: owner %s, want root:root", dirOwner)
	}

	// /etc/ssh/auth_principals/postern — mode 0644, owner root:root
	princMode, princOwner := tgt.statPath(ctx, t, "/etc/ssh/auth_principals/postern")
	if princMode != "644" {
		t.Errorf("/etc/ssh/auth_principals/postern: mode %s, want 644", princMode)
	}
	if princOwner != "root:root" {
		t.Errorf("/etc/ssh/auth_principals/postern: owner %s, want root:root", princOwner)
	}

	// ── Verify sshd -T -C AuthorizedPrincipalsFile ────────────────────
	// sshd -T -C user=postern expands %u to "postern" for the user context.
	t.Log("sshd -T -C AuthorizedPrincipalsFile doğrulaması...")
	apfOut, rc := tgt.execShellWithRC(ctx, t,
		"sshd -T -C user=postern,host=localhost 2>/dev/null | grep -i '^authorizedprincipalsfile' | sed -r 's/\\x1b\\[[0-9;]*[a-zA-Z]//g'")
	apfClean := strings.TrimSpace(apfOut)
	if rc != 0 || !strings.Contains(apfClean, "/etc/ssh/auth_principals/%u") {
		t.Errorf("sshd -T -C AuthorizedPrincipalsFile beklenen pathi içermiyor: %s (rc=%d)", apfClean, rc)
	} else {
		t.Logf("AuthorizedPrincipalsFile doğrulandı: %s", apfClean)
	}

	t.Log("sertleştirme doğrulaması başarılı")
}
