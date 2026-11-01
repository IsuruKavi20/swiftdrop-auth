# SwiftDrop Auth Service: production image.
# Two stages: a JDK builds the jar, a small JRE-only image runs it (no compiler, no Maven, no source in production).
# Build:  docker build -t swiftdrop-auth:1.0.0 .
# ARM (Oracle Ampere) from an x86 laptop:  docker buildx build --platform linux/arm64 -t <registry>/swiftdrop-auth:<tag> --push .
# Run:    see README "Run the Docker image" (every secret comes from environment variables, never from the image).

# ---- stage 1: build ----
# Always runs on the BUILD machine's own processor ($BUILDPLATFORM): a jar is the same on every CPU, so Maven runs
# at full speed even when the final image is for ARM (no slow CPU emulation for the compile)
FROM --platform=$BUILDPLATFORM eclipse-temurin:25-jdk-noble AS build
WORKDIR /workspace

# Dependencies first: this layer is cached and only rebuilt when pom.xml changes
COPY .mvn .mvn
COPY mvnw pom.xml ./
RUN ./mvnw -q -B dependency:go-offline

# Then the code. Tests run before release with "mvnw verify" (they need Docker for Testcontainers, not available here)
COPY src src
RUN ./mvnw -q -B -DskipTests package \
    && java -Djarmode=tools -jar target/auth-*.jar extract --layers --launcher --destination extracted

# ---- stage 2: run ----
# The TARGET processor (amd64 on a laptop, arm64 for Oracle Ampere): only this small stage is built for it
FROM eclipse-temurin:25-jre-noble

# Never run as root: a fixed, unprivileged user with no login shell
RUN groupadd --system --gid 10001 app \
    && useradd --system --uid 10001 --gid app --no-create-home --shell /usr/sbin/nologin app
WORKDIR /app

# Layers from least to most often changed, so an update usually only ships the small "application" layer
COPY --from=build /workspace/extracted/dependencies/ ./
COPY --from=build /workspace/extracted/spring-boot-loader/ ./
COPY --from=build /workspace/extracted/snapshot-dependencies/ ./
COPY --from=build /workspace/extracted/application/ ./

USER 10001:10001
EXPOSE 9000

# Use up to 75% of the container's memory limit; crash cleanly (and get restarted) instead of limping on OOM
ENV JAVA_TOOL_OPTIONS="-XX:MaxRAMPercentage=75 -XX:+ExitOnOutOfMemoryError"
# No default profile on purpose: the platform must set SPRING_PROFILES_ACTIVE=prod (fail closed otherwise)
ENTRYPOINT ["java", "org.springframework.boot.loader.launch.JarLauncher"]
