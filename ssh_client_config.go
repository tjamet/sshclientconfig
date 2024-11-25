package sshClientConfig

import (
	"crypto/rand"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/kevinburke/ssh_config"
	"github.com/spf13/afero"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/term"
)

const (
	sshAuthSock = "SSH_AUTH_SOCK"
	none        = "none"
)

var (
	// Log allows customers to hook their own logging function into the library
	// to receive logs. By default, discarded.
	// Logs are only emitted for invisible events and handled errors.
	// Errors returned to the library user will not be logged and should be handled by the caller.
	Log = func(level int, format string, args ...interface{}) {}
	fs  = afero.NewOsFs()
)

type LogLevel int

type SSHClientConfig struct {
	// Configuration paths to lookup for configuration.
	LookupPaths []string
}

// UserConfigPath returns the folder holding the user SSH configuration files.
// Usually $HOME/.ssh
func UserConfigPath(subFolders ...string) string {
	return filepath.Join(append([]string{os.Getenv("HOME"), ".ssh"}, subFolders...)...)
}

// NewSSHClientConfig creates a new SSHClientConfig object.
//
// It implements the path specification implemented by the BSD SSH client:
//
//	Specifies an alternative per-user configuration file.
//	If a configuration file is given on the command line, the system-wide configuration file (/etc/ssh/ssh_config) will be ignored.
//	The default for the per-user configuration file is ~/.ssh/config.  If set to “none”, no configuration files will be read.
//
// Configuration items are resolved following the SSH documentation:
// ssh(1) obtains configuration data from the following sources in the following order:

// 1.   command-line options
// 2.   user's configuration file (~/.ssh/config)
// 3.   system-wide configuration file (/etc/ssh/ssh_config)

// For each parameter, the first obtained value will be used.
func NewSSHClientConfig(path string) *SSHClientConfig {
	if path == none {
		Log(5, "SSHConfig path is set to %s, no configuration files will be read", none)
		return &SSHClientConfig{}
	}
	if path == "" {
		return &SSHClientConfig{
			LookupPaths: []string{
				filepath.Join(UserConfigPath(), "config"),
				"/etc/ssh/ssh_config",
			},
		}
	}
	Log(5, "provided, excluding default user (~/.ssh/config) and system (/etc/ssh/ssh_config) paths")
	return &SSHClientConfig{
		LookupPaths: []string{path},
	}
}

type Override func(*ssh.ClientConfig)

func WithUser(user string) Override {
	return func(cfg *ssh.ClientConfig) {
		Log(5, "overriding user %s to %s", cfg.User, user)
		cfg.User = user
	}
}

func reKeyLimitBytes(limit string) (uint64, error) {
	factor := uint64(1)
	if len(limit) < 1 {
		return 0, errors.New("invalid limit format")
	}
	switch limit[len(limit)-1] {
	case 'K':
		factor = 1024
	case 'M':
		factor = 1024 * 1024
	case 'G':
		factor = 1024 * 1024 * 1024
	}
	if factor != 1 {
		limit = limit[:len(limit)-1]
	}
	parsed, err := strconv.ParseUint(limit, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("failed to parse RekeyLimit %s: %v", limit, err)
	}
	Log(5, "Found reKeyLimit %s, parsed as %d bytes", limit, factor*parsed)
	return factor * parsed, nil
}

func (c SSHClientConfig) setReKeyLimit(config *ssh.ClientConfig, limit string) error {
	s := strings.SplitN(strings.TrimSpace(limit), " ", 2)
	if len(s) > 0 {
		limit, err := reKeyLimitBytes(s[0])
		if err != nil {
			return err
		}
		config.RekeyThreshold = limit
		if len(s) > 1 {
			Log(4, "ignoring additional RekeyLimit value %s, not supported by golang ssh client config", strings.Join(s[1:], " "))
		}
	}
	return nil
}

type sshConfig struct {
	*ssh_config.Config
	path string
}

func (c SSHClientConfig) configs() ([]*sshConfig, error) {
	var configs []*sshConfig
	for _, path := range c.LookupPaths {
		// Load configuration from path
		f, err := fs.Open(path)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return nil, fmt.Errorf("unable to open SSH config file %s: %v", path, err)
		}
		cfg, err := ssh_config.Decode(f)
		if err != nil {
			return nil, fmt.Errorf("unable to decode SSH config file %s: %v", path, err)
		} else {
			configs = append(configs, &sshConfig{Config: cfg, path: path})
		}
	}
	return configs, nil
}

func (c SSHClientConfig) getConfigValue(host, key, dflt string) (string, error) {
	configs, err := c.configs()
	if err != nil {
		Log(2, "unable to get SSH config for host %s: %v, ignoring", host, err)
		return dflt, err
	}
	for _, cfg := range configs {
		val, err := cfg.Get(host, key)
		if err != nil {
			Log(4, "error getting %s config key from path %s: %v, ignoring", key, cfg.path, err)
			continue
		}
		if val != "" {
			return val, nil
		}
	}
	return dflt, nil
}

func ignoreError[T any](v T, _ error) T {
	return v
}

func (c SSHClientConfig) HostName(host string) string {
	return ignoreError(c.getConfigValue(host, "HostName", host))
}

func (c SSHClientConfig) Port(host, port string) string {
	if port != "" {
		return port
	}
	return ignoreError(c.getConfigValue(host, "Port", "22"))
}

func (c SSHClientConfig) DialAddr(addr string) string {
	port := ""
	s := strings.Split(addr, ":")
	if len(s) > 2 {
		Log(4, "unsupported dial address format %s, ignoring", addr)
		return addr
	}
	host := s[0]
	if len(s) > 1 {
		port = s[1]
	}
	return fmt.Sprintf("%s:%s", c.HostName(host), c.Port(host, port))
}

func replaceEnvVars(s string) (string, error) {
	// ENVIRONMENT VARIABLES
	//  Arguments to some keywords can be expanded at runtime from environment variables on the client by enclosing them in ${}, for example ${HOME}/.ssh would refer to the
	//  user's .ssh directory.  If a specified environment variable does not exist then an error will be returned and the setting for that keyword will be ignored.

	//  The keywords CertificateFile, ControlPath, IdentityAgent, IdentityFile, KnownHostsCommand, and UserKnownHostsFile support environment variables.  The keywords
	//  LocalForward and RemoteForward support environment variables only for Unix domain socket paths.
	if strings.HasPrefix(s, "~/") {
		s = filepath.Join(os.Getenv("HOME"), s[2:])
	}
	if s == "" {
		return "", nil
	}
	o := strings.Builder{}
	envKey := strings.Builder{}
	inEnv := false
	var prev rune
	for _, r := range s {
		switch r {
		case '}':
			if inEnv {
				inEnv = false
				envVal, ok := os.LookupEnv(envKey.String())
				if !ok {
					return "", fmt.Errorf("invalid environment expansion %s", envKey.String())
				}
				o.WriteString(envVal)
				envKey.Reset()
			} else {
				o.WriteRune(r)
			}
		case '{':
			if prev == '$' {
				inEnv = true
			} else {
				o.WriteRune(r)
			}
		case '$':
			if prev == '$' {
				return "", fmt.Errorf("syntax error. Unexpected $$ in string %s", s)
			}
		default:
			if prev == '$' {
				return "", fmt.Errorf("syntax error. '$' in expected to be followed by '{' in string %s", s)
			}
			if inEnv {
				envKey.WriteRune(r)
			} else {
				o.WriteRune(r)
			}
		}
		prev = r
	}
	if prev == '$' {
		return "", fmt.Errorf("syntax error. '$' in expected to be followed by '{' in string %s", s)
	}
	return o.String(), nil
}

func (c SSHClientConfig) identityAgentPath(configs []*sshConfig, host string) (string, error) {
	for _, cfg := range configs {
		// IdentityAgent
		//          Specifies the UNIX-domain socket used to communicate with the authentication agent.

		//          This option overrides the SSH_AUTH_SOCK environment variable and can be used to select a specific agent.  Setting the socket name to none disables the use of
		//          an authentication agent.  If the string "SSH_AUTH_SOCK" is specified, the location of the socket will be read from the SSH_AUTH_SOCK environment variable.
		//          Otherwise if the specified value begins with a ‘$’ character, then it will be treated as an environment variable containing the location of the socket.

		//          Arguments to IdentityAgent may use the tilde syntax to refer to a user's home directory, the tokens described in the TOKENS section and environment variables
		//          as described in the ENVIRONMENT VARIABLES section.
		identityAgent, err := cfg.Get(host, "IdentityAgent")
		if err != nil {
			Log(4, "error getting IdentityAgent config key from path %s: %v, ignoring", cfg.path, err)
			continue
		}
		if identityAgent == "" {
			continue
		}
		if identityAgent == none {
			Log(5, "IdentityAgent is set to %s, disabling agent", none)
			return "", nil
		}
		if identityAgent == sshAuthSock {
			Log(5, "IdentityAgent is set to %s, using environment variable", sshAuthSock)
			break
		}
		// TODO: handle tokens
		identityAgent, err = replaceEnvVars(identityAgent)
		if err != nil {
			return "", err
		}
		return identityAgent, nil
	}
	return os.Getenv(sshAuthSock), nil
}

func (c SSHClientConfig) identityFiles(configs []*sshConfig, host string) ([]string, error) {
	candidates := []string{}
	for _, cfg := range configs {
		// IdentityFile
		// Specifies a file from which the user's DSA, ECDSA, authenticator-hosted ECDSA, Ed25519, authenticator-hosted Ed25519 or RSA authentication identity is read.
		// The default is ~/.ssh/id_dsa, ~/.ssh/id_ecdsa, ~/.ssh/id_ecdsa_sk, ~/.ssh/id_ed25519, ~/.ssh/id_ed25519_sk and ~/.ssh/id_rsa.  Additionally, any identities
		// represented by the authentication agent will be used for authentication unless IdentitiesOnly is set.  If no certificates have been explicitly specified by
		// CertificateFile, ssh(1) will try to load certificate information from the filename obtained by appending -cert.pub to the path of a specified IdentityFile.

		// Arguments to IdentityFile may use the tilde syntax to refer to a user's home directory or the tokens described in the TOKENS section.

		// It is possible to have multiple identity files specified in configuration files; all these identities will be tried in sequence.  Multiple IdentityFile
		// directives will add to the list of identities tried (this behaviour differs from that of other configuration directives).

		// IdentityFile may be used in conjunction with IdentitiesOnly to select which identities in an agent are offered during authentication.  IdentityFile may also
		// be used in conjunction with CertificateFile in order to provide any certificate also needed for authentication with the identity.
		files, err := cfg.GetAll(host, "IdentityFile")
		if err != nil {
			Log(4, "error getting IdentityFile config key from path %s: %v, ignoring", cfg.path, err)
			continue
		}
		if len(files) > 0 {
			for _, file := range files {
				file, err = replaceEnvVars(file)
				if err != nil {
					return nil, err
				}
				candidates = append(candidates, file)
			}
		}
	}
	// Prefer files provided by IdentityFiles
	candidates = append(
		candidates,
		UserConfigPath("id_dsa"),
		UserConfigPath("id_ecdsa"),
		UserConfigPath("id_ecdsa_sk"),
		UserConfigPath("id_ed25519"),
		UserConfigPath("id_ed25519_sk"),
		UserConfigPath("id_xmsshost"),
		UserConfigPath("id_rsa"),
	)
	return candidates, nil
}

func newPublicKeysCallback(identitiesOnly bool, agentPath string, identityFiles []string) func() ([]ssh.Signer, error) {
	return func() ([]ssh.Signer, error) {
		keys := []ssh.Signer{}
		if !identitiesOnly {
			agentKeys, err := loadAgentKeys(agentPath)
			if err != nil {
				Log(2, "error loading agent keys: %v, ignoring", err)
			}
			keys = append(keys, agentKeys...)
		}
		for _, path := range identityFiles {
			key, err := loadPrivateKeyFromFS(path)
			if err != nil {
				Log(2, "error loading private key %s: %v, ignoring", path, err)
			} else if key != nil {
				keys = append(keys, key)
			}
		}
		return keys, nil
	}
}

func (c SSHClientConfig) parsePublicKeyConfig(configs []*sshConfig, host string) (identitiesOnly bool, agentPath string, identityFiles []string) {
	agentPath, err := c.identityAgentPath(configs, host)
	if err != nil {
		Log(2, "error getting IdentityAgent config key: %v, ignoring", err)
	} else if agentPath != "" {
		Log(5, "Will attempt keys from agent %s", agentPath)
	}
	identityFiles, err = c.identityFiles(configs, host)
	if err != nil {
		Log(2, "error getting IdentityFile config key: %v, ignoring", err)
	} else if len(identityFiles) > 0 {
		for _, path := range identityFiles {
			Log(5, "Will attempt key from %s", path)
		}
	}
	identitiesOnly = false
	for _, cfg := range configs {
		// IdentitiesOnly
		// Specifies that ssh(1) should only use the configured authentication identity and certificate files (either the default files, or those explicitly configured
		// 	in the ssh_config files or passed on the ssh(1) command-line), even if ssh-agent(1) or a PKCS11Provider or SecurityKeyProvider offers more identities.  The
		// 	argument to this keyword must be yes or no (the default).  This option is intended for situations where ssh-agent offers many different identities.
		val, err := cfg.Get(host, "IdentitiesOnly")
		if err != nil {
			Log(4, "error getting IdentitiesOnly config key from path %s: %v, ignoring and consider false", cfg.path, err)
		} else {
			switch val {
			case "yes":
				identitiesOnly = true
			case "no":
				identitiesOnly = false
			default:
				Log(4, "invalid value %s for IdentitiesOnly, ignoring and consider false", val)
			}
		}
	}
	return
}

func (c SSHClientConfig) addPublicKeys(config *ssh.ClientConfig, configs []*sshConfig, host string) {
	config.Auth = append(
		config.Auth,
		ssh.PublicKeysCallback(newPublicKeysCallback(c.parsePublicKeyConfig(configs, host))),
	)
}

func loadAgentKeys(agentPath string) ([]ssh.Signer, error) {
	conn, err := net.Dial("unix", agentPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	signers, err := agent.NewClient(conn).Signers()
	if err != nil {
		return nil, err
	}
	o := []ssh.Signer{}
	for _, s := range signers {
		_, err := s.Sign(rand.Reader, []byte(""))
		if err != nil {
			Log(2, "error signing data: %v, ignoring", err)
		} else {
			o = append(o, s)
		}
	}
	return o, nil
}

func loadPrivateKeyFromFS(path string) (ssh.Signer, error) {
	privateKey, err := afero.ReadFile(fs, path)
	if err != nil {
		if os.IsNotExist(err) {
			Log(4, "private key %s does not exist, ignoring", path)
			return nil, nil
		}
		return nil, err
	}
	signer, err := ssh.ParsePrivateKey(privateKey)
	if err != nil {
		return nil, err
	}
	return signer, nil
}

func (c SSHClientConfig) SSHClientConfig(host string, overrides ...Override) (*ssh.ClientConfig, error) {
	configs, err := c.configs()
	if err != nil {
		return nil, err
	}

	config := &ssh.ClientConfig{
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}

	for _, cfg := range configs {
		// RekeyLimit
		// Specifies the maximum amount of data that may be transmitted before the session key is renegotiated, optionally followed by a maximum amount of time that may
		// pass before the session key is renegotiated.  The first argument is specified in bytes and may have a suffix of ‘K’, ‘M’, or ‘G’ to indicate Kilobytes,
		// Megabytes, or Gigabytes, respectively.  The default is between ‘1G’ and ‘4G’, depending on the cipher.  The optional second value is specified in seconds and
		// may use any of the units documented in the TIME FORMATS section of sshd_config(5).  The default value for RekeyLimit is default none, which means that
		// rekeying is performed after the cipher's default amount of data has been sent or received and no time based rekeying is done.
		limit, err := cfg.Get(host, "RekeyLimit")
		if err != nil {
			Log(4, "error getting RekeyLimit config key from path %s: %v, ignoring", cfg.path, err)
		} else if limit != "" {
			if err := c.setReKeyLimit(config, limit); err != nil {
				return nil, err
			}
			Log(5, "found RekeyLimit config from path %s", cfg.path)
			break
		}
	}

	for _, cfg := range configs {
		u, err := cfg.Get(host, "User")
		if err != nil {
			Log(4, "error getting User config key from path %s: %v, ignoring", cfg.path, err)
		} else if u != "" {
			config.User = u
			Log(5, "found User config from path %s", cfg.path)
			break
		}
	}

	c.addPublicKeys(config, configs, host)

	if term.IsTerminal(int(os.Stdin.Fd())) {
		Log(5, "stdin is a terminal, adding password auth prompt")
		config.Auth = append(
			config.Auth,
			ssh.PasswordCallback(func() (string, error) {
				fmt.Printf("%s@%s's password:\n", config.User, c.HostName(host))
				password, err := term.ReadPassword(int(os.Stdin.Fd()))
				if err != nil {
					return "", err
				}
				return string(password), nil
			}),
		)
	} else {
		Log(5, "stdin is not a terminal, not adding password auth prompt")
	}

	for _, cfg := range configs {
		//      IgnoreUnknown
		// Specifies a pattern-list of unknown options to be ignored if they are encountered in configuration parsing.  This may be used to suppress errors if
		// ssh_config contains options that are unrecognised by ssh(1).  It is recommended that IgnoreUnknown be listed early in the configuration file as it will not
		// be applied to unknown options that appear before it.
		ignored, err := cfg.Get(host, "IgnoreUnknown")
		if err != nil {
			Log(4, "error getting IgnoreUnknown config key from path %s: %v, ignoring", cfg.path, err)
		}
		ignoredKeys, err := NewPatternList(ignored)
		if err != nil {
			return nil, err
		}

		// TODO: KeyExchanges, Ciphers, MACs
		for _, unsupported := range []string{
			"ForwardAgent",
			"ProxyCommand",
			"ProxyJump",
			"KeyAlgorithms",
			"PubkeyAcceptedAlgorithms",
			"PubkeyAuthentication",
			"HostKeyAlgorithms",
			"CASignatureAlgorithms",
			"Ciphers",
			"MACs",
			"KnownHostsCommand",
			"CertificateFile",
		} {
			if ignoredKeys.Match(unsupported) {
				Log(5, "Unsupported key %s from path %s is ignored, skipping", unsupported, cfg.path)
				continue
			}

			if c, err := cfg.Get(host, unsupported); err == nil && c != "" {
				return nil, fmt.Errorf("unsupported configuration option %s", unsupported)
			}
		}
	}

	for _, override := range overrides {
		override(config)
	}

	return config, nil
}

type Pattern struct {
	str string
	exp *regexp.Regexp
	not bool
}

var specialChars = map[rune]struct{}{
	'.': {},
	'+': {},
	'(': {},
	')': {},
	'|': {},
	'[': {},
	']': {},
	'{': {},
	'}': {},
	'^': {},
	'$': {},
}

func special(r rune) bool {
	_, ok := specialChars[r]
	return ok
}

func NewPattern(s string) (*Pattern, error) {
	p := &Pattern{str: s, not: strings.HasPrefix(s, "!")}
	if p.not {
		s = s[1:]
	}
	buf := strings.Builder{}
	buf.WriteRune('^')
	for _, r := range s {
		switch r {
		case '*':
			buf.WriteString(".*")
		case '?':
			buf.WriteString(".")
		default:
			// borrowing from QuoteMeta here.
			if special(r) {
				buf.WriteByte('\\')
			}
			buf.WriteRune(r)
		}
	}
	buf.WriteRune('$')
	r, err := regexp.Compile(buf.String())
	if err != nil {
		return nil, err
	}
	p.exp = r
	return p, nil
}

func (p *Pattern) Matches(text string) bool {
	if p.not {
		return !p.RawMatches(text)
	}
	return p.RawMatches(text)
}

func (p *Pattern) RawMatches(text string) bool {
	return p.exp.MatchString(text)
}

func (p *Pattern) Not() bool {
	return p.not
}

type PatternList []*Pattern

func NewPatternList(s string) (PatternList, error) {
	pl := PatternList{}
	for _, pattern := range strings.Split(s, ",") {
		p, err := NewPattern(pattern)
		if err != nil {
			return nil, err
		}
		pl = append(pl, p)
	}
	return pl, nil
}

func (pl PatternList) Match(text string) bool {
	for _, p := range pl {
		if p.RawMatches(text) {
			return !p.Not()
		}
	}
	return false
}
