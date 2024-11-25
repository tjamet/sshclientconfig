package sshclientconfig

import (
	"crypto"
	"crypto/dsa"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"net"
	"testing"

	"github.com/kevinburke/ssh_config"
	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

func TestUserConfigPath_NoSubfolders(t *testing.T) {
	t.Setenv("HOME", "/home/user")
	assert.Equal(t, "/home/user/.ssh", UserConfigPath())
}

func TestUserConfigPath_WithSubfolders(t *testing.T) {
	t.Setenv("HOME", "/home/user")
	assert.Equal(t, "/home/user/.ssh/sub1/sub2", UserConfigPath("sub1", "sub2"))
}

func TestUserConfigPath_EmptyHome(t *testing.T) {
	t.Setenv("HOME", "")
	assert.Equal(t, ".ssh/sub1", UserConfigPath("sub1"))
}

func TestNewSSHClientConfig_DefaultPath(t *testing.T) {
	t.Setenv("HOME", "/home/user")
	config := NewSSHClientConfig("")
	expectedPaths := []string{
		"/home/user/.ssh/config",
		"/etc/ssh/ssh_config",
	}
	assert.Equal(t, expectedPaths, config.LookupPaths)
}

func TestNewSSHClientConfig_NonePath(t *testing.T) {
	config := NewSSHClientConfig("none")
	assert.Empty(t, config.LookupPaths)
}

func TestNewSSHClientConfig_CustomPath(t *testing.T) {
	config := NewSSHClientConfig("/custom/path")
	expectedPaths := []string{"/custom/path"}
	assert.Equal(t, expectedPaths, config.LookupPaths)
}

func TestWithUser(t *testing.T) {
	config := &ssh.ClientConfig{
		User: "oldUser",
	}
	override := WithUser("newUser")
	override(config)
	assert.Equal(t, "newUser", config.User)
}

func TestWithUser_Empty(t *testing.T) {
	config := &ssh.ClientConfig{
		User: "oldUser",
	}
	override := WithUser("")
	override(config)
	assert.Equal(t, "", config.User)
}

func TestWithUser_NoChange(t *testing.T) {
	config := &ssh.ClientConfig{
		User: "oldUser",
	}
	override := WithUser("oldUser")
	override(config)
	assert.Equal(t, "oldUser", config.User)
}

func checkReKeyLimitBytes(t *testing.T, limit string, expected uint64) {
	t.Helper()
	result, err := reKeyLimitBytes(limit)
	assert.NoError(t, err)
	assert.Equal(t, expected, result)
}

func checkReKeyLimitByteInError(t *testing.T, limit string) {
	t.Helper()
	result, err := reKeyLimitBytes(limit)
	assert.Error(t, err)
	assert.Equal(t, uint64(0), result)
}

func TestReKeyLimitBytes(t *testing.T) {
	checkReKeyLimitBytes(t, "1024", 1024)
	checkReKeyLimitBytes(t, "1K", 1024)
	checkReKeyLimitBytes(t, "1M", 1024*1024)
	checkReKeyLimitBytes(t, "1G", 1024*1024*1024)
	checkReKeyLimitByteInError(t, "1T")
	checkReKeyLimitByteInError(t, "invalid")
	checkReKeyLimitByteInError(t, "")
}
func TestSetReKeyLimit_ValidLimits(t *testing.T) {
	config := &ssh.ClientConfig{}
	sshConfig := SSHClientConfig{}

	err := sshConfig.setReKeyLimit(config, "1M")
	assert.NoError(t, err)
	assert.Equal(t, uint64(1024*1024), config.RekeyThreshold)
}

func TestSetReKeyLimit_InvalidLimits(t *testing.T) {
	config := &ssh.ClientConfig{}
	sshConfig := SSHClientConfig{}

	err := sshConfig.setReKeyLimit(config, "invalid")
	assert.Error(t, err)
}
func TestIdentityAgentPath_FromEnvVar(t *testing.T) {
	t.Setenv("SSH_AUTH_SOCK", "/tmp/ssh-auth.sock")
	cfg := SSHClientConfig{}
	configs := []*sshConfig{
		{
			Config: &ssh_config.Config{},
			path:   "/home/user/.ssh/config",
		},
	}
	agentPath, err := cfg.identityAgentPath(configs, "example.com")
	assert.NoError(t, err)
	assert.Equal(t, "/tmp/ssh-auth.sock", agentPath)
}

func TestIdentityAgentPath_PicksTheFirstAgentPath(t *testing.T) {
	// If the agent is set in the configuration file, the env variable is ignored
	t.Setenv("SSH_AUTH_SOCK", "/tmp/ssh-auth.sock")
	t.Setenv("HOME", "/home/user")
	cfg := SSHClientConfig{}
	exampleHostPattern, err := ssh_config.NewPattern("example.com")
	require.NoError(t, err)
	otherHostPath, err := ssh_config.NewPattern("other.example.com")
	require.NoError(t, err)
	configs := []*sshConfig{
		{
			Config: &ssh_config.Config{
				Hosts: []*ssh_config.Host{
					{
						Patterns: []*ssh_config.Pattern{
							otherHostPath,
						},
						Nodes: []ssh_config.Node{
							&ssh_config.KV{
								Key:   "IdentityAgent",
								Value: "/not-used/agent.sock",
							},
						},
					},
				},
			},
			path: "/home/user/.ssh/config",
		},
		{
			Config: &ssh_config.Config{
				Hosts: []*ssh_config.Host{
					{
						Patterns: []*ssh_config.Pattern{
							exampleHostPattern,
						},
						Nodes: []ssh_config.Node{
							&ssh_config.KV{
								Key:   "User",
								Value: "user-name",
							},
						},
					},
				},
			},
			path: "/home/user/.ssh/config",
		},
		{
			Config: &ssh_config.Config{
				Hosts: []*ssh_config.Host{
					{
						Patterns: []*ssh_config.Pattern{
							exampleHostPattern,
						},
						Nodes: []ssh_config.Node{
							&ssh_config.KV{
								Key:   "IdentityAgent",
								Value: "~/agent.sock",
							},
						},
					},
				},
			},
			path: "/home/user/.ssh/config",
		},
	}
	agentPath, err := cfg.identityAgentPath(configs, "example.com")
	assert.NoError(t, err)
	assert.Equal(t, "/home/user/agent.sock", agentPath)
}

func TestIdentityAgentPath_UsesEnvironmentVariableWhenReferencedInPath(t *testing.T) {
	t.Setenv("SSH_AUTH_SOCK", "/tmp/ssh-auth.sock")
	cfg := SSHClientConfig{}
	exampleHostPattern, err := ssh_config.NewPattern("example.com")
	require.NoError(t, err)
	configs := []*sshConfig{
		{
			Config: &ssh_config.Config{
				Hosts: []*ssh_config.Host{
					{
						Patterns: []*ssh_config.Pattern{
							exampleHostPattern,
						},
						Nodes: []ssh_config.Node{
							&ssh_config.KV{
								Key:   "IdentityAgent",
								Value: sshAuthSock,
							},
						},
					},
				},
			},
			path: "/home/user/.ssh/config",
		},
	}
	agentPath, err := cfg.identityAgentPath(configs, "example.com")
	assert.NoError(t, err)
	assert.Equal(t, "/tmp/ssh-auth.sock", agentPath)
}

func TestIdentityAgentPath_DropsPathWhenNoneIsUsed(t *testing.T) {
	t.Setenv("SSH_AUTH_SOCK", "/tmp/ssh-auth.sock")
	cfg := SSHClientConfig{}
	exampleHostPattern, err := ssh_config.NewPattern("example.com")
	require.NoError(t, err)
	configs := []*sshConfig{
		{
			Config: &ssh_config.Config{
				Hosts: []*ssh_config.Host{
					{
						Patterns: []*ssh_config.Pattern{
							exampleHostPattern,
						},
						Nodes: []ssh_config.Node{
							&ssh_config.KV{
								Key:   "IdentityAgent",
								Value: none,
							},
						},
					},
				},
			},
			path: "/home/user/.ssh/config",
		},
	}
	agentPath, err := cfg.identityAgentPath(configs, "example.com")
	assert.NoError(t, err)
	assert.Equal(t, "", agentPath)
}

func checkPatternMatch(t *testing.T, pattern, text string, match bool) {
	t.Helper()
	p, err := NewPattern(pattern)
	require.NoError(t, err)
	assert.Equal(t, match, p.Matches(text))
}

func TestNewPattern(t *testing.T) {
	checkPatternMatch(t, "example.com", "example.com", true)
	checkPatternMatch(t, "example.com", "test.com", false)
	checkPatternMatch(t, "*.example.com", "sub.example.com", true)
	checkPatternMatch(t, "*.example.com", "example.com", false)
	checkPatternMatch(t, "!example.com", "example.com", false)
	checkPatternMatch(t, "!example.com", "test.com", true)
	checkPatternMatch(t, "example.*", "example.com", true)
	checkPatternMatch(t, "example.*", "example.org", true)
	checkPatternMatch(t, "example.*", "example", false)
	checkPatternMatch(t, "example?.com", "example1.com", true)
	checkPatternMatch(t, "example?.com", "example.com", false)
	checkPatternMatch(t, "example+", "example", false)
	checkPatternMatch(t, "example.", "examplew", false)
}

func checkPatternListMatch(t *testing.T, patterns, text string, match bool) {
	t.Helper()
	pl, err := NewPatternList(patterns)
	require.NoError(t, err)
	assert.Equal(t, match, pl.Match(text))
}

func TestNewPatternList(t *testing.T) {
	checkPatternListMatch(t, "example.com,*.test.com", "example.com", true)
	checkPatternListMatch(t, "example.com,*.test.com", "some.test.com", true)
	checkPatternListMatch(t, "example.com,test.com", "test.com", true)
	checkPatternListMatch(t, "example.com,!test.com,*test.com", "test.com", false)
	checkPatternListMatch(t, "example.com,*test.com", "other.com", false)
}

func withTestFs(t *testing.T, testFs afero.Fs) {
	t.Cleanup(
		func() {
			fs = afero.NewOsFs()
		},
	)
	fs = testFs
}

func writeTestFile(t *testing.T, fs afero.Fs, path, content string) {
	t.Helper()
	fd, err := fs.Create(path)
	require.NoError(t, err)
	_, err = fd.WriteString(content)
	require.NoError(t, err)
	fd.Close()
}

func TestHostConfig_NoConfigFiles(t *testing.T) {
	withTestFs(t, afero.NewMemMapFs())
	cfg := SSHClientConfig{
		LookupPaths: []string{
			"/path/to/ssh/config",
			"/other/path/to/ssh/config",
		},
	}
	configs, err := cfg.configs()
	assert.NoError(t, err)
	assert.Empty(t, configs)
}

func TestHostConfig_InvalidConfigFile(t *testing.T) {
	fs := afero.NewMemMapFs()
	writeTestFile(t, fs, "/path/to/ssh/config", "Include /this/path/[abc/is/not/a/valid/pattern\n")
	withTestFs(t, fs)
	cfg := SSHClientConfig{
		LookupPaths: []string{
			"/path/to/ssh/config",
			"/other/path/to/ssh/config",
		},
	}
	configs, err := cfg.configs()
	assert.Error(t, err)
	assert.Empty(t, configs)
}

func TestHostConfig_LoadsAllConfigFiles(t *testing.T) {
	fs := afero.NewMemMapFs()
	writeTestFile(t, fs, "/path/to/ssh/config", "Host example.com\n")
	writeTestFile(t, fs, "/other/path/to/ssh/config", "Host other.com\n")
	withTestFs(t, fs)
	cfg := SSHClientConfig{
		LookupPaths: []string{
			"/path/to/ssh/config",
			"/other/path/to/ssh/config",
		},
	}
	configs, err := cfg.configs()
	assert.NoError(t, err)
	assert.Len(t, configs, 2)
	assert.Equal(t, "/path/to/ssh/config", configs[0].path)
	assert.Equal(t, "/other/path/to/ssh/config", configs[1].path)

	assert.Equal(t, "example.com", configs[0].Config.Hosts[len(configs[0].Config.Hosts)-1].Patterns[0].String())
	assert.Equal(t, "other.com", configs[1].Config.Hosts[len(configs[0].Config.Hosts)-1].Patterns[0].String())

}

func TestReplaceEnvVars_EmptyString(t *testing.T) {
	t.Setenv("HOME", "/home/user")
	result, err := replaceEnvVars("")
	assert.NoError(t, err)
	assert.Equal(t, "", result)
}

func TestReplaceEnvVars_HomeDir(t *testing.T) {
	t.Setenv("HOME", "/home/user")
	result, err := replaceEnvVars("~/mydir")
	assert.NoError(t, err)
	assert.Equal(t, "/home/user/mydir", result)
}

func TestReplaceEnvVars_SpecialCharacters(t *testing.T) {
	t.Setenv("HOME", "/home/user")
	result, err := replaceEnvVars("${HOME}/mydir/{}")
	assert.NoError(t, err)
	assert.Equal(t, "/home/user/mydir/{}", result)
}

func TestReplaceEnvVars_HomeEnvVar(t *testing.T) {
	t.Setenv("HOME", "/home/user")
	result, err := replaceEnvVars("${HOME}/mydir")
	assert.NoError(t, err)
	assert.Equal(t, "/home/user/mydir", result)
}

func TestReplaceEnvVars_CustomEnvVar(t *testing.T) {
	t.Setenv("MY_VAR", "my_value")
	result, err := replaceEnvVars("${MY_VAR}/mydir")
	assert.NoError(t, err)
	assert.Equal(t, "my_value/mydir", result)
}

func TestReplaceEnvVars_UnknownEnvVar(t *testing.T) {
	result, err := replaceEnvVars("${UNKNOWN_VAR}/mydir")
	assert.Error(t, err)
	assert.Equal(t, "", result)
}

func TestReplaceEnvVars_MultipleEnvVars(t *testing.T) {
	t.Setenv("HOME", "/home/user")
	t.Setenv("MY_VAR", "my_value")
	result, err := replaceEnvVars("${HOME}/mydir/${MY_VAR}")
	assert.NoError(t, err)
	assert.Equal(t, "/home/user/mydir/my_value", result)
}

func TestReplaceEnvVars_MixedKnownAndUnknownEnvVars(t *testing.T) {
	t.Setenv("HOME", "/home/user")
	result, err := replaceEnvVars("${HOME}/mydir/${THIS_VARIABLE_SHOULD_NOT_EXIST}")
	assert.Error(t, err)
	assert.Equal(t, "", result)
}

func TestReplaceEnvVars_InvalidSyntax_DoubleDollar(t *testing.T) {
	t.Setenv("HOME", "/home/user")
	result, err := replaceEnvVars("${HOME}/mydir/$$")
	assert.Error(t, err)
	assert.Equal(t, "", result)
}

func TestReplaceEnvVars_InvalidSyntax_SingleDollar(t *testing.T) {
	t.Setenv("HOME", "/home/user")
	result, err := replaceEnvVars("${HOME}/mydir/$")
	assert.Error(t, err)
	assert.Equal(t, "", result)
}

func TestReplaceEnvVars_InvalidSyntax_EmptyBraces(t *testing.T) {
	t.Setenv("HOME", "/home/user")
	result, err := replaceEnvVars("${HOME}/mydir/${}")
	assert.Error(t, err)
	assert.Equal(t, "", result)
}

func TestIdentitiesFiles(t *testing.T) {
	t.Setenv("HOME", "/home/user")
	t.Setenv("TMPDIR", "/tmp")

	fs := afero.NewMemMapFs()
	writeTestFile(t, fs, "/path/to/ssh/config", "IdentityFile /tmp/id_rsa\nHost example.com\n\tIdentityFile /tmp/id_rsa2\n\tIdentityFile ${TMPDIR}/id_rsa3")
	writeTestFile(t, fs, "/other/path/to/ssh/config", "Host example.com\n\tIdentityFile /tmp/id_ecdsa\n")
	withTestFs(t, fs)
	cfg := SSHClientConfig{
		LookupPaths: []string{
			"/path/to/ssh/config",
			"/other/path/to/ssh/config",
		},
	}
	configs, err := cfg.configs()
	require.NoError(t, err)

	identities, err := cfg.identityFiles(configs, "example.com")
	assert.NoError(t, err)
	assert.Equal(t, []string{
		"/tmp/id_rsa",
		"/tmp/id_rsa2",
		"/tmp/id_rsa3",
		"/tmp/id_ecdsa",
		"/home/user/.ssh/id_dsa",
		"/home/user/.ssh/id_ecdsa",
		"/home/user/.ssh/id_ecdsa_sk",
		"/home/user/.ssh/id_ed25519",
		"/home/user/.ssh/id_ed25519_sk",
		"/home/user/.ssh/id_xmsshost",
		"/home/user/.ssh/id_rsa",
	}, identities)
}
func TestHostName_WithoutConfigReturnsOriginalHost(t *testing.T) {
	withTestFs(t, afero.NewMemMapFs())
	cfg := SSHClientConfig{
		LookupPaths: []string{
			"/path/to/ssh/config",
			"/other/path/to/ssh/config",
		},
	}
	host := cfg.HostName("example.com")
	assert.Equal(t, "example.com", host)
}

func TestHostName(t *testing.T) {
	fs := afero.NewMemMapFs()
	writeTestFile(t, fs, "/path/to/ssh/config", "Host example.com\n\tHostName overridden.com\n")
	writeTestFile(t, fs, "/other/path/to/ssh/config", "Host example.com\n\tHostName overridden2.com\n")
	withTestFs(t, fs)
	cfg := SSHClientConfig{
		LookupPaths: []string{
			"/path/to/ssh/config",
			"/other/path/to/ssh/config",
		},
	}
	assert.Equal(t, "overridden.com", cfg.HostName("example.com"))
	assert.Equal(t, "other.com", cfg.HostName("other.com"))
}

func TestPort(t *testing.T) {
	fs := afero.NewMemMapFs()
	writeTestFile(t, fs, "/path/to/ssh/config", "Host example.com\n\tPort 2222\n")
	writeTestFile(t, fs, "/other/path/to/ssh/config", "Host example.com\n\tPort 4444\n")
	withTestFs(t, fs)
	cfg := SSHClientConfig{
		LookupPaths: []string{
			"/path/to/ssh/config",
			"/other/path/to/ssh/config",
		},
	}
	assert.Equal(t, "2222", cfg.Port("example.com", ""))
	assert.Equal(t, "22", cfg.Port("example.com", "22"))
}

func TestDialAddress(t *testing.T) {
	t.Setenv("HOME", "/home/user")
	fs := afero.NewMemMapFs()
	writeTestFile(t, fs, "/home/user/.ssh/config", "Host example.com\n\tHostName overridden.com\n\tPort 2222\n")
	withTestFs(t, fs)
	cfg := NewSSHClientConfig("")
	assert.Equal(t, "overridden.com:2222", cfg.DialAddr("example.com"))
	assert.Equal(t, "overridden.com:4444", cfg.DialAddr("example.com:4444"))
	assert.Equal(t, "other.com:22", cfg.DialAddr("other.com"))
}

func TestAddPublicKeys(t *testing.T) {
	t.Setenv("HOME", "/home/user")

	fs := afero.NewMemMapFs()
	writeTestFile(t, fs, "/home/user/.ssh/id_private_host", "public_key")
	writeTestFile(t, fs, "/home/user/.ssh/config", "Host example.com\n\tIdentityFile ~/.ssh/id_private_host\n")
	withTestFs(t, fs)

	cfg := NewSSHClientConfig("")
	configs, err := cfg.configs()
	require.NoError(t, err)

	sshConfig := &ssh.ClientConfig{}
	cfg.addPublicKeys(sshConfig, configs, "example.com")

	assert.Len(t, sshConfig.Auth, 1)
}

func TestParsePublicKeyConfig(t *testing.T) {
	t.Setenv("HOME", "/home/user")
	t.Setenv(sshAuthSock, "/var/run/ssh-agent.sock")

	fs := afero.NewMemMapFs()
	writeTestFile(t, fs, "/home/user/.ssh/id_private_host", "public_key")
	writeTestFile(t, fs, "/home/user/.ssh/config", `
Host 127.0.0.1
    IdentityAgent ~/.ssh/agent.sock
Host example.com
	IdentityFile ~/.ssh/id_private_host
	IdentitiesOnly yes
Host other.com
	IdentitiesOnly invalid
`)
	withTestFs(t, fs)

	cfg := NewSSHClientConfig("")
	configs, err := cfg.configs()
	require.NoError(t, err)

	identitiesOnly, agentPath, identitiesFiles := cfg.parsePublicKeyConfig(configs, "example.com")
	assert.True(t, identitiesOnly)
	assert.Equal(t, "/var/run/ssh-agent.sock", agentPath)
	assert.Equal(t,
		[]string{
			"/home/user/.ssh/id_private_host",
			"/home/user/.ssh/id_dsa",
			"/home/user/.ssh/id_ecdsa",
			"/home/user/.ssh/id_ecdsa_sk",
			"/home/user/.ssh/id_ed25519",
			"/home/user/.ssh/id_ed25519_sk",
			"/home/user/.ssh/id_xmsshost",
			"/home/user/.ssh/id_rsa",
		},
		identitiesFiles,
	)

	identitiesOnly, agentPath, identitiesFiles = cfg.parsePublicKeyConfig(configs, "other.com")
	assert.False(t, identitiesOnly)
	assert.Equal(t, "/var/run/ssh-agent.sock", agentPath)
	assert.Equal(t,
		[]string{
			"/home/user/.ssh/id_dsa",
			"/home/user/.ssh/id_ecdsa",
			"/home/user/.ssh/id_ecdsa_sk",
			"/home/user/.ssh/id_ed25519",
			"/home/user/.ssh/id_ed25519_sk",
			"/home/user/.ssh/id_xmsshost",
			"/home/user/.ssh/id_rsa",
		},
		identitiesFiles,
	)

	identitiesOnly, agentPath, identitiesFiles = cfg.parsePublicKeyConfig(configs, "127.0.0.1")
	assert.False(t, identitiesOnly)
	assert.Equal(t, "/home/user/.ssh/agent.sock", agentPath)
	assert.Equal(t,
		[]string{
			"/home/user/.ssh/id_dsa",
			"/home/user/.ssh/id_ecdsa",
			"/home/user/.ssh/id_ecdsa_sk",
			"/home/user/.ssh/id_ed25519",
			"/home/user/.ssh/id_ed25519_sk",
			"/home/user/.ssh/id_xmsshost",
			"/home/user/.ssh/id_rsa",
		},
		identitiesFiles,
	)
}

func TestNewPublicKeysCallback(t *testing.T) {

	fs := afero.NewMemMapFs()
	priv, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	require.NoError(t, err)
	writePrivateKey(t, fs, "/home/user/.ssh/id_ecdsa", priv)
	rsaPriv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	writePrivateKey(t, fs, "/home/user/.ssh/id_rsa", rsaPriv)

	withTestFs(t, fs)

	sshAgent := agent.NewKeyring()
	l, err := net.Listen("unix", "/tmp/.test-ssh-agent.sock")
	require.NoError(t, err)
	defer l.Close()
	require.NoError(t, err)
	agentPrivateKey := &dsa.PrivateKey{}
	require.NoError(t, dsa.GenerateParameters(&agentPrivateKey.Parameters, rand.Reader, dsa.L1024N160))
	require.NoError(t, dsa.GenerateKey(agentPrivateKey, rand.Reader))
	sshAgent.Add(agent.AddedKey{PrivateKey: agentPrivateKey})
	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			go agent.ServeAgent(sshAgent, conn)
		}
	}()

	t.Run("When the config does not claim IdentitiesOnly", func(t *testing.T) {
		signers, err := newPublicKeysCallback(false, "/tmp/.test-ssh-agent.sock", []string{"/home/user/.ssh/id_rsa", "/home/user/.ssh/id_dsa", "/home/user/.ssh/id_ecdsa"})()
		require.NoError(t, err)
		require.Len(t, signers, 3)

		assert.Equal(t, "ssh-dss", signers[0].PublicKey().Type())
		assert.Equal(t, "ssh-rsa", signers[1].PublicKey().Type())
		assert.Equal(t, "ecdsa-sha2-nistp521", signers[2].PublicKey().Type())
	})

	t.Run("When the config does claims IdentitiesOnly", func(t *testing.T) {
		signers, err := newPublicKeysCallback(true, "/tmp/.test-ssh-agent.sock", []string{"/home/user/.ssh/id_rsa", "/home/user/.ssh/id_dsa", "/home/user/.ssh/id_ecdsa"})()
		require.NoError(t, err)
		require.Len(t, signers, 2)
		assert.Equal(t, "ssh-rsa", signers[0].PublicKey().Type())
		assert.Equal(t, "ecdsa-sha2-nistp521", signers[1].PublicKey().Type())
	})

	t.Run("When the agent path does not exist", func(t *testing.T) {
		signers, err := newPublicKeysCallback(false, "/home/user/.ssh/agent.sock", []string{"/home/user/.ssh/id_rsa", "/home/user/.ssh/id_dsa", "/home/user/.ssh/id_ecdsa"})()
		require.NoError(t, err)
		require.Len(t, signers, 2)
		assert.Equal(t, "ssh-rsa", signers[0].PublicKey().Type())
		assert.Equal(t, "ecdsa-sha2-nistp521", signers[1].PublicKey().Type())
	})

}

func TestSSHClientConfig(t *testing.T) {
	t.Setenv("HOME", "/home/user")
	fs := afero.NewMemMapFs()
	writeTestFile(t, fs, "/home/user/.ssh/config", `
Host 127.0.0.1
    IdentityAgent ~/.ssh/agent.sock
Host example.com
	IdentityFile ~/.ssh/id_private_host
	IdentitiesOnly yes
	RekeyLimit 2M
	User john-doe
Host ignored.forwardagent.com
	ForwardAgent yes
	IgnoreUnknown ForwardAgent
Host forwardagent.com
	ForwardAgent yes
`)
	withTestFs(t, fs)
	cfg := NewSSHClientConfig("")

	t.Run("When the host is not found and all used features are supported", func(t *testing.T) {
		sshConfig, err := cfg.SSHClientConfig("example.com")
		require.NoError(t, err)

		assert.Equal(t, "john-doe", sshConfig.User)
		assert.Equal(t, 2*1024*1024, int(sshConfig.RekeyThreshold))
	})

	t.Run("When the host is not found and all unimplemented features are ignored", func(t *testing.T) {
		_, err := cfg.SSHClientConfig("ignored.forwardagent.com")
		require.NoError(t, err)
	})

	t.Run("When the host is not found and all unimplemented features are ignored", func(t *testing.T) {
		_, err := cfg.SSHClientConfig("forwardagent.com")
		require.Error(t, err)
	})

}

func writePrivateKey(t *testing.T, fs afero.Fs, path string, priv crypto.PrivateKey) {
	t.Helper()
	fd, err := fs.Create(path)
	require.NoError(t, err)
	data, err := marshallPrivateKey(priv)
	require.NoError(t, err)

	require.NoError(
		t,
		pem.Encode(
			fd,
			&pem.Block{
				Type:  privateKeyType(priv),
				Bytes: data,
			},
		),
	)

	_, err = fd.Write(data)

	require.NoError(t, err)
	fd.Close()
}

func marshallPrivateKey(priv crypto.PrivateKey) ([]byte, error) {
	switch k := priv.(type) {
	case *rsa.PrivateKey:
		return x509.MarshalPKCS1PrivateKey(k), nil
	case *ecdsa.PrivateKey:
		return x509.MarshalECPrivateKey(k)
	case ed25519.PrivateKey:
		return x509.MarshalPKCS8PrivateKey(priv)
	default:
		return nil, errors.New("unknown private key type")
	}
}

func privateKeyType(priv crypto.PrivateKey) string {
	switch priv.(type) {
	case *rsa.PrivateKey:
		return "RSA PRIVATE KEY"
	case *ecdsa.PrivateKey:
		return "EC PRIVATE KEY"
	case ed25519.PrivateKey:
		return "PRIVATE KEY"
	default:
		return ""
	}
}
