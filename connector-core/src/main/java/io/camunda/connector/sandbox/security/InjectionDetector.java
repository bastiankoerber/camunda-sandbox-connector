package io.camunda.connector.sandbox.security;

import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.text.Normalizer;
import java.util.List;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * Detects command injection attempts in user input.
 * This is a critical security component that must catch all injection vectors.
 */
@Slf4j
@Component
public class InjectionDetector {

    /**
     * A pattern with a user-friendly description for error messages.
     */
    private record SecurityPattern(Pattern pattern, String description) {
        boolean matches(String input) {
            return pattern.matcher(input).find();
        }
    }

    // Unicode characters that look like dangerous ASCII characters (homoglyphs)
    // These must be detected and blocked to prevent bypass attempts
    private static final Set<Character> DANGEROUS_UNICODE = Set.of(
            '\u037E',  // Greek question mark (looks like ;)
            '\uFF1B',  // Fullwidth semicolon
            '\uFF5C',  // Fullwidth vertical line (|)
            '\uFF06',  // Fullwidth ampersand (&)
            '\uFF1C',  // Fullwidth less-than (<)
            '\uFF1E',  // Fullwidth greater-than (>)
            '\uFF40',  // Fullwidth grave accent (`)
            '\uFF04',  // Fullwidth dollar sign ($)
            '\u2028',  // Line separator
            '\u2029',  // Paragraph separator
            '\u0085',  // Next line (NEL)
            '\u00A0',  // Non-breaking space (can hide in commands)
            '\u2060',  // Word joiner (invisible)
            '\u200B',  // Zero-width space
            '\u200C',  // Zero-width non-joiner
            '\u200D',  // Zero-width joiner
            '\uFEFF'   // Byte order mark (can be used to hide content)
    );

    // Shell metacharacters that can be used for injection - with user-friendly descriptions
    // NOTE: Order matters! More specific patterns (like ||) must come before general patterns (like |)
    private static final List<SecurityPattern> INJECTION_PATTERNS = List.of(
            // Command chaining - check || BEFORE | to get correct error message
            new SecurityPattern(Pattern.compile(";"), 
                "Semicolons (;) are not allowed - they can be used to chain multiple commands"),
            new SecurityPattern(Pattern.compile("\\|\\|"), 
                "The || operator is not allowed - use single commands without chaining"),
            new SecurityPattern(Pattern.compile("\\|"), 
                "Pipe characters (|) are not allowed - use single commands without piping"),
            new SecurityPattern(Pattern.compile("&&"), 
                "The && operator is not allowed - use single commands without chaining"),
            
            // Command substitution - check $(( before $( to distinguish arithmetic from command substitution
            new SecurityPattern(Pattern.compile("\\$\\(\\("), 
                "Arithmetic expansion $(()) is not allowed - use literal numbers"),
            new SecurityPattern(Pattern.compile("\\$\\("), 
                "Command substitution $() is not allowed - use direct command arguments"),
            new SecurityPattern(Pattern.compile("`"), 
                "Backticks (`) are not allowed - they can execute embedded commands"),
            
            // Redirections - check >> before > to get correct error message
            new SecurityPattern(Pattern.compile(">>"), 
                "Append redirection (>>) is not allowed - the sandbox controls file output"),
            new SecurityPattern(Pattern.compile("2>&1"), 
                "Stream redirection (2>&1) is not allowed - stderr is captured automatically"),
            new SecurityPattern(Pattern.compile("&>"), 
                "Combined redirection (&>) is not allowed - output is captured automatically"),
            new SecurityPattern(Pattern.compile(">\\("), 
                "Process substitution >() is not allowed"),
            new SecurityPattern(Pattern.compile(">"), 
                "Output redirection (>) is not allowed - the sandbox controls file output"),
            new SecurityPattern(Pattern.compile("<<"), 
                "Here documents (<<) are not allowed - provide input as arguments"),
            new SecurityPattern(Pattern.compile("<\\("), 
                "Process substitution <() is not allowed"),
            new SecurityPattern(Pattern.compile("<"), 
                "Input redirection (<) is not allowed - provide input as command arguments"),
            
            // Variable expansion
            new SecurityPattern(Pattern.compile("\\$\\{"), 
                "Variable expansion ${} is not allowed - use literal values instead"),
            new SecurityPattern(Pattern.compile("\\$[A-Za-z_][A-Za-z0-9_]*"), 
                "Environment variable references ($VAR) are not allowed - use literal values"),
            
            // Backgrounding
            new SecurityPattern(Pattern.compile("&\\s*$"), 
                "Background execution (&) is not allowed - commands run in foreground"),
            
            // History expansion
            new SecurityPattern(Pattern.compile("!"), 
                "History expansion (!) is not allowed - use explicit commands"),
            
            // Brace expansion
            new SecurityPattern(Pattern.compile("\\{[^}]*,[^}]*\\}"), 
                "Brace expansion {a,b} is not allowed - specify files explicitly"),
            
            // Arithmetic expansion - $[[ format (older bash syntax)
            new SecurityPattern(Pattern.compile("\\$\\[\\["), 
                "Arithmetic expansion is not allowed - use literal numbers")
    );

    // Patterns that are suspicious - with user-friendly descriptions
    private static final List<SecurityPattern> SUSPICIOUS_PATTERNS = List.of(
            // Path traversal
            new SecurityPattern(Pattern.compile("\\.\\./"), 
                "Path traversal (../) is not allowed - use absolute paths within the sandbox"),
            new SecurityPattern(Pattern.compile("/etc/"), 
                "Access to system configuration (/etc/) is not allowed"),
            new SecurityPattern(Pattern.compile("/proc/"), 
                "Access to process information (/proc/) is not allowed"),
            new SecurityPattern(Pattern.compile("/sys/"), 
                "Access to system internals (/sys/) is not allowed"),
            new SecurityPattern(Pattern.compile("/dev/"), 
                "Access to device files (/dev/) is not allowed"),
            new SecurityPattern(Pattern.compile("/tmp/"), 
                "Access to /tmp/ is restricted - use the sandbox working directory"),
            
            // Linux /proc attack vectors
            new SecurityPattern(Pattern.compile("/proc/self/"), 
                "Access to /proc/self/ is not allowed - this could leak process information"),
            new SecurityPattern(Pattern.compile("/proc/\\d+/"), 
                "Access to other process information (/proc/[pid]/) is not allowed"),
            new SecurityPattern(Pattern.compile("/proc/version"), 
                "Access to kernel version information is not allowed"),
            new SecurityPattern(Pattern.compile("/proc/meminfo"), 
                "Access to memory information is not allowed"),
            new SecurityPattern(Pattern.compile("/proc/cpuinfo"), 
                "Access to CPU information is not allowed"),
            
            // Linux /sys attack vectors
            new SecurityPattern(Pattern.compile("/sys/class/"), 
                "Access to device class information is not allowed"),
            new SecurityPattern(Pattern.compile("/sys/kernel/"), 
                "Access to kernel parameters is not allowed"),
            new SecurityPattern(Pattern.compile("/sys/fs/cgroup/"), 
                "Access to cgroup filesystem is not allowed"),
            
            // Container escape attempts
            new SecurityPattern(Pattern.compile("/var/run/docker"), 
                "Access to Docker socket is not allowed"),
            new SecurityPattern(Pattern.compile("docker\\.sock"), 
                "Access to Docker socket is not allowed"),
            new SecurityPattern(Pattern.compile("/run/containerd/"), 
                "Access to container runtime is not allowed"),
            new SecurityPattern(Pattern.compile("\\bnsenter\\b"), 
                "The nsenter command is not allowed - namespace manipulation is blocked"),
            new SecurityPattern(Pattern.compile("\\bunshare\\b"), 
                "The unshare command is not allowed - namespace manipulation is blocked"),
            
            // Encoded characters
            new SecurityPattern(Pattern.compile("%00"), 
                "Null bytes (including URL-encoded %00) are not allowed"),
            new SecurityPattern(Pattern.compile("%0[aAdD]", Pattern.CASE_INSENSITIVE), 
                "Encoded newlines/carriage returns are not allowed"),
            new SecurityPattern(Pattern.compile("%2e%2e", Pattern.CASE_INSENSITIVE), 
                "URL-encoded path traversal (%2e%2e = ..) is not allowed"),
            new SecurityPattern(Pattern.compile("%252e", Pattern.CASE_INSENSITIVE), 
                "Double-encoded characters are not allowed"),
            new SecurityPattern(Pattern.compile("\\\\x[0-9a-fA-F]{2}"), 
                "Hex escape sequences (\\xNN) are not allowed"),
            new SecurityPattern(Pattern.compile("\\\\[0-7]{1,3}"), 
                "Octal escape sequences are not allowed"),
            
            // Dangerous commands
            new SecurityPattern(Pattern.compile("base64\\s+-d"), 
                "Base64 decoding is not allowed - it can be used to hide malicious commands"),
            new SecurityPattern(Pattern.compile("\\|\\s*sh"), 
                "Piping to shell (| sh) is not allowed"),
            new SecurityPattern(Pattern.compile("\\|\\s*bash"), 
                "Piping to bash (| bash) is not allowed"),
            new SecurityPattern(Pattern.compile("\\brm\\s+-rf"), 
                "Recursive forced deletion (rm -rf) is not allowed"),
            new SecurityPattern(Pattern.compile("\\bchmod\\b"), 
                "Changing file permissions (chmod) is not allowed"),
            new SecurityPattern(Pattern.compile("\\bchown\\b"), 
                "Changing file ownership (chown) is not allowed"),
            new SecurityPattern(Pattern.compile("\\bsudo\\b"), 
                "Privilege escalation (sudo) is not allowed"),
            new SecurityPattern(Pattern.compile("\\bsu\\b"), 
                "User switching (su) is not allowed"),
            new SecurityPattern(Pattern.compile("\\bnc\\b"), 
                "Network tools like netcat (nc) are not allowed"),
            new SecurityPattern(Pattern.compile("\\bnetcat\\b"), 
                "Network tools like netcat are not allowed"),
            new SecurityPattern(Pattern.compile("\\bcurl.*\\|.*sh"), 
                "Downloading and executing scripts (curl | sh) is not allowed"),
            new SecurityPattern(Pattern.compile("\\bwget.*\\|.*sh"), 
                "Downloading and executing scripts (wget | sh) is not allowed"),
            
            // Linux-specific injection vectors
            new SecurityPattern(Pattern.compile("LD_PRELOAD"), 
                "LD_PRELOAD environment variable is not allowed - it can inject malicious code"),
            new SecurityPattern(Pattern.compile("LD_LIBRARY_PATH"), 
                "LD_LIBRARY_PATH manipulation is not allowed"),
            new SecurityPattern(Pattern.compile("LD_AUDIT"), 
                "LD_AUDIT environment variable is not allowed"),
            new SecurityPattern(Pattern.compile("LD_DEBUG"), 
                "LD_DEBUG environment variable is not allowed"),
            
            // macOS-specific injection vectors
            new SecurityPattern(Pattern.compile("DYLD_INSERT_LIBRARIES"), 
                "DYLD_INSERT_LIBRARIES is not allowed - it can inject malicious code on macOS"),
            new SecurityPattern(Pattern.compile("DYLD_LIBRARY_PATH"), 
                "DYLD_LIBRARY_PATH manipulation is not allowed"),
            new SecurityPattern(Pattern.compile("DYLD_FRAMEWORK_PATH"), 
                "DYLD_FRAMEWORK_PATH manipulation is not allowed"),
            new SecurityPattern(Pattern.compile("DYLD_FALLBACK_"), 
                "DYLD environment variables are not allowed on macOS")
    );

    /**
     * Detect injection attempts in the input string.
     *
     * @param input The string to check
     * @throws SecurityException if an injection attempt is detected
     */
    public void detectInjection(String input) throws SecurityException {
        if (input == null || input.isEmpty()) {
            return;
        }

        log.debug("Checking for injection patterns in input (length={})", input.length());

        // Check for excessively long input first (fail fast)
        if (input.length() > 10000) {
            throw new SecurityException(
                "Input is too long. Maximum allowed length is 10,000 characters. " +
                "Please reduce the size of your command or arguments.");
        }

        // 1. Check for dangerous Unicode characters (homoglyphs) BEFORE normalization
        for (char c : input.toCharArray()) {
            if (DANGEROUS_UNICODE.contains(c)) {
                log.warn("Dangerous Unicode character detected: U+{} in input: {}", 
                        String.format("%04X", (int) c), maskInput(input));
                throw new SecurityException(
                    "Invalid character detected. Your input contains a Unicode character " +
                    "(U+" + String.format("%04X", (int) c) + ") that is not allowed. " +
                    "Please use only standard ASCII characters.");
            }
        }

        // 2. Normalize Unicode to NFKC form to catch bypass attempts
        String normalized = Normalizer.normalize(input, Normalizer.Form.NFKC);
        
        if (!normalized.equals(input)) {
            log.warn("Input contains non-normalized Unicode that could be hiding injection: {}", 
                    maskInput(input));
        }

        // 3. Check for control characters (except tab which is allowed)
        for (char c : input.toCharArray()) {
            if (Character.isISOControl(c) && c != '\t') {
                throw new SecurityException(
                    "Control characters are not allowed in commands. " +
                    "Your input contains a control character (ASCII " + (int) c + "). " +
                    "Please use only printable characters.");
            }
        }

        // 4. Check for direct injection patterns in BOTH original and normalized
        checkInjectionPatterns(input);
        if (!normalized.equals(input)) {
            checkInjectionPatterns(normalized);
        }

        // 5. Check for suspicious patterns
        checkSuspiciousPatterns(input);
        if (!normalized.equals(input)) {
            checkSuspiciousPatterns(normalized);
        }

        log.debug("No injection patterns detected");
    }

    /**
     * Check input against injection patterns.
     */
    private void checkInjectionPatterns(String input) {
        for (SecurityPattern sp : INJECTION_PATTERNS) {
            if (sp.matches(input)) {
                log.warn("Injection pattern detected: {} in input: {}", 
                        sp.pattern().pattern(), maskInput(input));
                throw new SecurityException(sp.description());
            }
        }
    }

    /**
     * Check input against suspicious patterns.
     */
    private void checkSuspiciousPatterns(String input) {
        for (SecurityPattern sp : SUSPICIOUS_PATTERNS) {
            if (sp.matches(input)) {
                log.warn("Suspicious pattern detected: {} in input: {}", 
                        sp.pattern().pattern(), maskInput(input));
                throw new SecurityException(sp.description());
            }
        }
    }

    /**
     * Check if a specific pattern is present (for more granular control).
     */
    public boolean containsPattern(String input, Pattern pattern) {
        return input != null && pattern.matcher(input).find();
    }

    /**
     * Mask input for safe logging.
     */
    private String maskInput(String input) {
        if (input == null) {
            return "[null]";
        }
        if (input.length() > 50) {
            return input.substring(0, 50) + "...";
        }
        return input;
    }
}
