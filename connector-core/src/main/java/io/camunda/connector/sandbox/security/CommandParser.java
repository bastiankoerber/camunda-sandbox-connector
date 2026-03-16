package io.camunda.connector.sandbox.security;

import io.camunda.connector.sandbox.model.ParsedCommand;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Parses CLI commands into executable and arguments.
 * Handles quoting and escaping while detecting shell-specific features.
 */
@Slf4j
@Component
public class CommandParser {

    // Pattern to match shell operators that indicate piping, chaining, etc.
    private static final Pattern SHELL_OPERATOR_PATTERN = Pattern.compile(
            "[;|&<>]|\\$\\(|`|\\\\\\n"
    );

    // Pattern to match quoted strings (single or double quotes)
    private static final Pattern QUOTED_STRING_PATTERN = Pattern.compile(
            "\"([^\"\\\\]|\\\\.)*\"|'[^']*'"
    );

    // Pattern for tokenizing command (handles quoted strings and regular tokens)
    private static final Pattern TOKEN_PATTERN = Pattern.compile(
            "\"([^\"\\\\]|\\\\.)*\"|'[^']*'|\\S+"
    );

    /**
     * Parse a command string into executable and arguments.
     *
     * @param command The raw command string
     * @return Parsed command with executable and arguments
     * @throws SecurityException if the command contains dangerous patterns
     */
    public ParsedCommand parse(String command) throws SecurityException {
        if (command == null || command.isBlank()) {
            throw new SecurityException("Command cannot be empty");
        }

        String trimmed = command.trim();
        log.debug("Parsing command: {}", maskForLogging(trimmed));

        // Check for shell-specific features in UNQUOTED parts only
        // First, remove all quoted strings, then check for operators
        boolean containsShellFeatures = containsUnquotedShellOperators(trimmed);
        if (containsShellFeatures) {
            log.warn("Command contains shell operators: {}", maskForLogging(trimmed));
            throw new SecurityException("Shell operators are not allowed. Use simple commands without pipes, redirects, or command chaining.");
        }

        // Tokenize the command
        List<String> tokens = tokenize(trimmed);
        if (tokens.isEmpty()) {
            throw new SecurityException("Command cannot be empty");
        }

        String executable = tokens.get(0);
        List<String> arguments = tokens.size() > 1 ? tokens.subList(1, tokens.size()) : List.of();

        // Validate executable name
        validateExecutableName(executable);

        return ParsedCommand.builder()
                .executable(executable)
                .arguments(new ArrayList<>(arguments))
                .rawCommand(command)
                .containsShellFeatures(containsShellFeatures)
                .build();
    }
    
    /**
     * Check if the command contains shell operators in unquoted parts.
     * Shell operators inside quoted strings are allowed (e.g., jq filters with |).
     */
    private boolean containsUnquotedShellOperators(String command) {
        // Replace all quoted strings with placeholders to check only unquoted parts
        String withoutQuotes = QUOTED_STRING_PATTERN.matcher(command).replaceAll("QUOTED_STRING");
        return SHELL_OPERATOR_PATTERN.matcher(withoutQuotes).find();
    }

    /**
     * Tokenize a command string, respecting quoted strings.
     */
    private List<String> tokenize(String command) {
        List<String> tokens = new ArrayList<>();
        Matcher matcher = TOKEN_PATTERN.matcher(command);

        while (matcher.find()) {
            String token = matcher.group();
            // Remove surrounding quotes and unescape
            token = unquote(token);
            tokens.add(token);
        }

        return tokens;
    }

    /**
     * Remove quotes and unescape a token.
     * Handles both fully-quoted strings and embedded quotes (e.g., --opt="value").
     */
    private String unquote(String token) {
        if (token.length() < 2) {
            return token;
        }

        char first = token.charAt(0);
        char last = token.charAt(token.length() - 1);

        if (first == '"' && last == '"') {
            // Double-quoted string - process escape sequences
            String inner = token.substring(1, token.length() - 1);
            return unescapeDoubleQuoted(inner);
        } else if (first == '\'' && last == '\'') {
            // Single-quoted string - no escape processing
            return token.substring(1, token.length() - 1);
        }
        
        // Handle embedded quotes (e.g., --option="value" or -var-file="file.tfvars")
        // Remove quotes from the value part
        if (token.contains("=\"") && token.endsWith("\"")) {
            int eqPos = token.indexOf("=\"");
            String prefix = token.substring(0, eqPos + 1);
            String quotedValue = token.substring(eqPos + 1);
            return prefix + unquote(quotedValue);
        } else if (token.contains("='") && token.endsWith("'")) {
            int eqPos = token.indexOf("='");
            String prefix = token.substring(0, eqPos + 1);
            String quotedValue = token.substring(eqPos + 1);
            return prefix + unquote(quotedValue);
        }

        return token;
    }

    /**
     * Process escape sequences in double-quoted strings.
     */
    private String unescapeDoubleQuoted(String s) {
        StringBuilder sb = new StringBuilder();
        boolean escaped = false;

        for (char c : s.toCharArray()) {
            if (escaped) {
                switch (c) {
                    case 'n' -> sb.append('\n');
                    case 't' -> sb.append('\t');
                    case 'r' -> sb.append('\r');
                    case '\\' -> sb.append('\\');
                    case '"' -> sb.append('"');
                    default -> {
                        sb.append('\\');
                        sb.append(c);
                    }
                }
                escaped = false;
            } else if (c == '\\') {
                escaped = true;
            } else {
                sb.append(c);
            }
        }

        if (escaped) {
            sb.append('\\');
        }

        return sb.toString();
    }

    /**
     * Validate the executable name is safe.
     */
    private void validateExecutableName(String executable) throws SecurityException {
        // Must not be empty
        if (executable == null || executable.isBlank()) {
            throw new SecurityException("Executable name cannot be empty");
        }

        // Must not contain path separators (enforces use of PATH)
        if (executable.contains("/") || executable.contains("\\")) {
            throw new SecurityException("Absolute or relative paths are not allowed. Use tool names only.");
        }

        String lower = executable.toLowerCase();
        
        // Must not be a shell
        if (lower.equals("sh") || lower.equals("bash") || lower.equals("zsh") || 
            lower.equals("csh") || lower.equals("tcsh") || lower.equals("ksh") ||
            lower.equals("fish") || lower.equals("dash") || lower.equals("ash")) {
            throw new SecurityException("Direct shell invocation is not allowed");
        }

        // Must not be an interpreter that can execute arbitrary code
        if (lower.equals("eval") || lower.equals("exec") || lower.equals("source")) {
            throw new SecurityException("Command execution utilities are not allowed");
        }

        // Block scripting language interpreters that can execute arbitrary code
        if (lower.equals("python") || lower.equals("python2") || lower.equals("python3") ||
            lower.startsWith("python2.") || lower.startsWith("python3.") ||
            lower.equals("ruby") || lower.startsWith("ruby2.") || lower.startsWith("ruby3.") ||
            lower.equals("perl") || lower.equals("perl5") || lower.startsWith("perl5.") ||
            lower.equals("node") || lower.equals("nodejs") || lower.equals("npm") || lower.equals("npx") ||
            lower.equals("lua") || lower.equals("luajit") || lower.startsWith("lua5.") ||
            lower.equals("php") || lower.startsWith("php5") || lower.startsWith("php7") || lower.startsWith("php8") ||
            lower.equals("tclsh") || lower.equals("wish") ||
            lower.equals("powershell") || lower.equals("pwsh")) {
            throw new SecurityException("Scripting language interpreters are not allowed: " + executable);
        }

        // Block utilities that can be used to execute arbitrary commands
        if (lower.equals("env") || lower.equals("xargs") || lower.equals("parallel") ||
            lower.equals("time") || lower.equals("timeout") || lower.equals("strace") ||
            lower.equals("ltrace") || lower.equals("watch") || lower.equals("nohup") ||
            lower.equals("osascript") || lower.equals("automator")) {
            throw new SecurityException("Command execution utilities are not allowed: " + executable);
        }

        // Block Linux namespace/container manipulation tools (container escape vectors)
        if (lower.equals("nsenter") || lower.equals("unshare") || lower.equals("setns") ||
            lower.equals("chroot") || lower.equals("pivot_root") || lower.equals("capsh") ||
            lower.equals("setcap") || lower.equals("getcap")) {
            throw new SecurityException("Namespace/capability manipulation tools are not allowed: " + executable);
        }

        // Block file editors that can spawn shells or execute commands
        if (lower.equals("vi") || lower.equals("vim") || lower.equals("nvim") ||
            lower.equals("nano") || lower.equals("emacs") || lower.equals("ed") ||
            lower.equals("ex") || lower.equals("pico")) {
            throw new SecurityException("Interactive editors are not allowed: " + executable);
        }

        // Block compilers and build tools that could compile and execute code
        if (lower.equals("gcc") || lower.equals("g++") || lower.equals("clang") ||
            lower.equals("make") || lower.equals("cmake") || lower.equals("ninja") ||
            lower.equals("cc") || lower.equals("ld") || lower.equals("as")) {
            throw new SecurityException("Compilers and build tools are not allowed: " + executable);
        }

        // Validate characters - only alphanumeric, dash, underscore, dot
        if (!executable.matches("^[a-zA-Z0-9._-]+$")) {
            throw new SecurityException("Executable name contains invalid characters");
        }

        // Length limit
        if (executable.length() > 64) {
            throw new SecurityException("Executable name is too long");
        }
    }

    /**
     * Mask sensitive parts of command for logging.
     */
    private String maskForLogging(String command) {
        if (command == null) {
            return "[null]";
        }
        if (command.length() > 100) {
            return command.substring(0, 100) + "...";
        }
        return command;
    }
}
