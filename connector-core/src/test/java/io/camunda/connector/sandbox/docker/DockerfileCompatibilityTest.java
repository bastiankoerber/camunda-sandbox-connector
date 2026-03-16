package io.camunda.connector.sandbox.docker;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.assertj.core.api.Assertions.*;

/**
 * Tests to ensure Docker build compatibility between stages.
 * 
 * <p>These tests verify that the Dockerfile maintains compatibility between
 * build and runtime stages, preventing issues like:
 * <ul>
 *   <li>glibc vs musl incompatibility (Debian vs Alpine)</li>
 *   <li>Library version mismatches</li>
 *   <li>Missing runtime dependencies</li>
 * </ul>
 * 
 * <p>IMPORTANT: nsjail is compiled with glibc on Debian and CANNOT run on Alpine
 * (musl libc). This test ensures we don't accidentally break this.
 */
@DisplayName("Dockerfile Compatibility Tests")
class DockerfileCompatibilityTest {

    private static final Path PROJECT_ROOT = Path.of(System.getProperty("user.dir")).getParent();
    private static final Path DOCKERFILE_PATH = PROJECT_ROOT.resolve("docker/Dockerfile");
    
    private static String dockerfileContent;
    
    // Known glibc-based images
    private static final List<String> GLIBC_BASE_IMAGES = List.of(
        "debian",
        "ubuntu",
        "eclipse-temurin:.*-jre$",           // Default temurin is Debian-based
        "eclipse-temurin:.*-jammy",          // Ubuntu 22.04
        "eclipse-temurin:.*-focal",          // Ubuntu 20.04
        "eclipse-temurin:.*-noble",          // Ubuntu 24.04
        "openjdk:.*-slim$",                  // Debian slim
        "openjdk:.*-buster",
        "openjdk:.*-bullseye",
        "openjdk:.*-bookworm",
        "amazoncorretto",
        "azul/zulu-openjdk"
    );
    
    // Known musl-based images (INCOMPATIBLE with glibc binaries)
    private static final List<String> MUSL_BASE_IMAGES = List.of(
        "alpine",
        ".*-alpine.*"
    );

    @BeforeAll
    static void loadDockerfile() throws IOException {
        if (Files.exists(DOCKERFILE_PATH)) {
            dockerfileContent = Files.readString(DOCKERFILE_PATH);
        } else {
            // Try relative path from connector-core
            Path altPath = Path.of("../docker/Dockerfile");
            if (Files.exists(altPath)) {
                dockerfileContent = Files.readString(altPath);
            } else {
                fail("Dockerfile not found at " + DOCKERFILE_PATH + " or " + altPath);
            }
        }
    }

    @Nested
    @DisplayName("Build Stage Compatibility")
    class BuildStageCompatibilityTests {

        @Test
        @DisplayName("nsjail builder stage should use glibc-based distro (Ubuntu or Debian)")
        void nsjailBuilderShouldUseGlibcDistro() {
            // Extract the nsjail-builder stage
            Pattern pattern = Pattern.compile(
                "FROM\\s+(\\S+)\\s+AS\\s+nsjail-builder",
                Pattern.CASE_INSENSITIVE
            );
            Matcher matcher = pattern.matcher(dockerfileContent);
            
            assertThat(matcher.find())
                .as("Dockerfile should have an nsjail-builder stage")
                .isTrue();
            
            String baseImage = matcher.group(1).toLowerCase();
            
            // nsjail must be built on glibc-based distro (Ubuntu or Debian)
            assertThat(baseImage)
                .as("nsjail-builder must use glibc-based image (Ubuntu or Debian), not Alpine (musl). " +
                    "nsjail compiled with glibc will NOT run on Alpine/musl. " +
                    "Found: " + baseImage)
                .satisfiesAnyOf(
                    img -> assertThat(img).contains("ubuntu"),
                    img -> assertThat(img).contains("debian")
                );
        }

        @Test
        @DisplayName("rootfs builder stage should use compatible libc")
        void rootfsBuilderShouldUseCompatibleLibc() {
            Pattern pattern = Pattern.compile(
                "FROM\\s+(\\S+)\\s+AS\\s+rootfs-builder",
                Pattern.CASE_INSENSITIVE
            );
            Matcher matcher = pattern.matcher(dockerfileContent);
            
            if (matcher.find()) {
                String baseImage = matcher.group(1);
                // rootfs-builder should use glibc-based distro (Ubuntu or Debian)
                assertThat(baseImage.toLowerCase())
                    .as("rootfs-builder should use glibc-based distro (Ubuntu or Debian). " +
                        "Found: " + baseImage)
                    .satisfiesAnyOf(
                        img -> assertThat(img).contains("ubuntu"),
                        img -> assertThat(img).contains("debian")
                    );
            }
        }
    }

    @Nested
    @DisplayName("Runtime Stage Compatibility")
    class RuntimeStageCompatibilityTests {

        @Test
        @DisplayName("Runtime stage must NOT use Alpine (musl incompatibility)")
        void runtimeStageMustNotUseAlpine() {
            // Find the runtime stage
            Pattern pattern = Pattern.compile(
                "FROM\\s+(\\S+)\\s+AS\\s+runtime",
                Pattern.CASE_INSENSITIVE
            );
            Matcher matcher = pattern.matcher(dockerfileContent);
            
            assertThat(matcher.find())
                .as("Dockerfile should have a runtime stage")
                .isTrue();
            
            String baseImage = matcher.group(1).toLowerCase();
            
            // CRITICAL: nsjail compiled on Debian CANNOT run on Alpine
            for (String muslPattern : MUSL_BASE_IMAGES) {
                assertThat(baseImage)
                    .as("Runtime stage MUST NOT use Alpine/musl-based image. " +
                        "nsjail is compiled with glibc and will fail with 'no such file or directory' " +
                        "when executed on musl-based systems. Found: " + baseImage)
                    .doesNotMatch(muslPattern);
            }
        }

        @Test
        @DisplayName("Runtime stage should use glibc-compatible base image")
        void runtimeStageShouldUseGlibcCompatibleImage() {
            Pattern pattern = Pattern.compile(
                "FROM\\s+(\\S+)\\s+AS\\s+runtime",
                Pattern.CASE_INSENSITIVE
            );
            Matcher matcher = pattern.matcher(dockerfileContent);
            
            assertThat(matcher.find()).isTrue();
            String baseImage = matcher.group(1).toLowerCase();
            
            boolean isGlibcCompatible = GLIBC_BASE_IMAGES.stream()
                .anyMatch(pattern1 -> baseImage.matches(".*" + pattern1.toLowerCase() + ".*") ||
                                      baseImage.contains(pattern1.replace(".*", "").toLowerCase()));
            
            assertThat(isGlibcCompatible)
                .as("Runtime base image must be glibc-compatible (Debian, Ubuntu, etc.). " +
                    "Found: " + baseImage + ". " +
                    "Acceptable patterns: " + GLIBC_BASE_IMAGES)
                .isTrue();
        }

        @Test
        @DisplayName("Runtime stage should use same Debian version as nsjail builder")
        void runtimeStageShouldMatchBuilderVersion() {
            // Extract nsjail-builder base image
            Pattern builderPattern = Pattern.compile(
                "FROM\\s+(debian:\\S+)\\s+AS\\s+nsjail-builder",
                Pattern.CASE_INSENSITIVE
            );
            Matcher builderMatcher = builderPattern.matcher(dockerfileContent);
            
            String builderDebianVersion = null;
            if (builderMatcher.find()) {
                builderDebianVersion = builderMatcher.group(1);
            }
            
            // Extract runtime base image
            Pattern runtimePattern = Pattern.compile(
                "FROM\\s+(\\S+)\\s+AS\\s+runtime",
                Pattern.CASE_INSENSITIVE
            );
            Matcher runtimeMatcher = runtimePattern.matcher(dockerfileContent);
            
            assertThat(runtimeMatcher.find()).isTrue();
            String runtimeImage = runtimeMatcher.group(1).toLowerCase();
            
            // If builder uses bookworm, runtime should also use bookworm
            if (builderDebianVersion != null && builderDebianVersion.contains("bookworm")) {
                assertThat(runtimeImage)
                    .as("Runtime must use the same Debian version (bookworm) as nsjail-builder " +
                        "to ensure library compatibility (especially protobuf). " +
                        "nsjail-builder uses: " + builderDebianVersion)
                    .contains("bookworm");
            }
        }

        @Test
        @DisplayName("Runtime stage should use specific Debian-based JRE")
        void runtimeStageShouldUseDebianJre() {
            Pattern pattern = Pattern.compile(
                "FROM\\s+(\\S+)\\s+AS\\s+runtime",
                Pattern.CASE_INSENSITIVE
            );
            Matcher matcher = pattern.matcher(dockerfileContent);
            
            assertThat(matcher.find()).isTrue();
            String baseImage = matcher.group(1);
            
            // Should use eclipse-temurin with a Debian variant (jammy, focal, bookworm)
            // or explicitly NOT alpine
            assertThat(baseImage)
                .as("Runtime should use a Debian/Ubuntu-based JRE image, not Alpine. " +
                    "Recommended: eclipse-temurin:21-jre-bookworm to match nsjail build")
                .satisfiesAnyOf(
                    img -> assertThat(img).containsIgnoringCase("jammy"),
                    img -> assertThat(img).containsIgnoringCase("focal"),
                    img -> assertThat(img).containsIgnoringCase("noble"),
                    img -> assertThat(img).containsIgnoringCase("bookworm"),
                    img -> assertThat(img).containsIgnoringCase("bullseye"),
                    img -> assertThat(img).containsIgnoringCase("debian"),
                    img -> assertThat(img).containsIgnoringCase("ubuntu")
                );
        }
    }

    @Nested
    @DisplayName("Library Dependencies")
    class LibraryDependencyTests {

        @Test
        @DisplayName("Runtime should install matching protobuf library version")
        void runtimeShouldInstallMatchingProtobuf() {
            // nsjail requires libprotobuf - version must match build environment
            // Debian bookworm uses libprotobuf32 (protobuf 3.21.x)
            // Debian bullseye uses libprotobuf23 (protobuf 3.12.x)
            // Ubuntu jammy uses libprotobuf23 (protobuf 3.12.x)
            
            // Check if using bookworm
            boolean usesBookworm = dockerfileContent.toLowerCase().contains("bookworm");
            
            if (usesBookworm) {
                assertThat(dockerfileContent)
                    .as("Debian bookworm requires libprotobuf32 (protobuf 3.21.x), not libprotobuf23")
                    .contains("libprotobuf32");
            } else {
                assertThat(dockerfileContent)
                    .as("Runtime stage must install protobuf library for nsjail")
                    .containsAnyOf("libprotobuf", "protobuf");
            }
        }

        @Test
        @DisplayName("Runtime should install libnl libraries")
        void runtimeShouldInstallLibnl() {
            // nsjail requires libnl for network namespace support
            assertThat(dockerfileContent)
                .as("Runtime stage must install libnl libraries for nsjail network namespaces")
                .containsAnyOf("libnl-3", "libnl3");
        }

        @Test
        @DisplayName("Runtime should install libseccomp")
        void runtimeShouldInstallLibseccomp() {
            // nsjail requires libseccomp for syscall filtering
            assertThat(dockerfileContent)
                .as("Runtime stage must install libseccomp for nsjail seccomp support")
                .contains("libseccomp");
        }

        @Test
        @DisplayName("Runtime should install libcap")
        void runtimeShouldInstallLibcap() {
            // nsjail requires libcap for capability management
            assertThat(dockerfileContent)
                .as("Runtime stage must install libcap for nsjail capability support")
                .containsAnyOf("libcap", "cap");
        }
    }

    @Nested
    @DisplayName("Consistency Checks")
    class ConsistencyChecks {

        @Test
        @DisplayName("nsjail binary should be copied from builder to runtime")
        void nsjailShouldBeCopiedToRuntime() {
            assertThat(dockerfileContent)
                .as("nsjail binary must be copied from nsjail-builder stage")
                .contains("COPY --from=nsjail-builder");
            
            assertThat(dockerfileContent)
                .as("nsjail should be copied to /usr/bin/nsjail")
                .containsPattern("COPY.*nsjail.*(/usr/bin/nsjail|/usr/local/bin/nsjail)");
        }

        @Test
        @DisplayName("nsjail binary should have execute permissions")
        void nsjailShouldBeExecutable() {
            assertThat(dockerfileContent)
                .as("nsjail binary should be made executable")
                .containsPattern("chmod.*(755|\\+x).*nsjail");
        }

        @Test
        @DisplayName("Environment variable SANDBOX_NSJAIL_PATH should match binary location")
        void nsjailPathEnvShouldMatchBinaryLocation() {
            // Find where nsjail is copied to
            Pattern copyPattern = Pattern.compile(
                "COPY.*nsjail.*/nsjail\\s+(/\\S+/nsjail)",
                Pattern.CASE_INSENSITIVE
            );
            Matcher copyMatcher = copyPattern.matcher(dockerfileContent);
            
            String nsjailBinaryPath = "/usr/bin/nsjail"; // default
            if (copyMatcher.find()) {
                nsjailBinaryPath = copyMatcher.group(1);
            }
            
            // Find the ENV setting
            Pattern envPattern = Pattern.compile(
                "SANDBOX_NSJAIL_PATH=(\\S+)",
                Pattern.CASE_INSENSITIVE
            );
            Matcher envMatcher = envPattern.matcher(dockerfileContent);
            
            if (envMatcher.find()) {
                String envPath = envMatcher.group(1);
                assertThat(envPath)
                    .as("SANDBOX_NSJAIL_PATH environment variable should point to actual nsjail location")
                    .isEqualTo(nsjailBinaryPath);
            }
        }
    }

    @Nested
    @DisplayName("Security Best Practices")
    class SecurityBestPractices {

        @Test
        @DisplayName("Should create non-root user for runtime")
        void shouldCreateNonRootUser() {
            assertThat(dockerfileContent)
                .as("Should create a non-root user (sandbox) for security")
                .containsAnyOf("adduser", "useradd");
            
            assertThat(dockerfileContent)
                .as("Should switch to non-root user")
                .contains("USER sandbox");
        }

        @Test
        @DisplayName("Should use tini as init system")
        void shouldUseTiniAsInit() {
            assertThat(dockerfileContent)
                .as("Should install tini for proper signal handling")
                .contains("tini");
            
            assertThat(dockerfileContent)
                .as("Should use tini as entrypoint")
                .containsPattern("ENTRYPOINT.*tini");
        }

        @Test
        @DisplayName("Should have health check configured")
        void shouldHaveHealthCheck() {
            assertThat(dockerfileContent)
                .as("Should configure health check for container orchestration")
                .containsIgnoringCase("HEALTHCHECK");
        }
    }
}
