package io.camunda.connector.sandbox.model;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

/**
 * Parsed and validated command ready for execution.
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class ParsedCommand {

    /**
     * The executable name (e.g., "curl", "python3")
     */
    private String executable;

    /**
     * List of arguments to pass to the executable
     */
    private List<String> arguments;

    /**
     * The original raw command string
     */
    private String rawCommand;

    /**
     * Whether the command contains any shell-specific features
     */
    private boolean containsShellFeatures;

    /**
     * Get the full command as a list (executable + arguments)
     */
    public List<String> toCommandList() {
        var result = new java.util.ArrayList<String>();
        result.add(executable);
        if (arguments != null) {
            result.addAll(arguments);
        }
        return result;
    }

    /**
     * Get the command as a shell-safe string representation
     */
    public String toSafeString() {
        StringBuilder sb = new StringBuilder(executable);
        if (arguments != null) {
            for (String arg : arguments) {
                sb.append(" ");
                // Quote arguments that contain spaces or special characters
                if (arg.contains(" ") || arg.contains("\"") || arg.contains("'")) {
                    sb.append("'").append(arg.replace("'", "'\\''")).append("'");
                } else {
                    sb.append(arg);
                }
            }
        }
        return sb.toString();
    }
}
