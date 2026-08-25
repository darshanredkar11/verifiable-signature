# SDP-1 — single-container deploy: Rust cdylib (the trust boundary) + Java Spring Boot
# (thin REST facade calling it via the JDK 22 Foreign Function & Memory API, in-process,
# no subprocess). One Dockerfile, one Render service, git push -> deploy.

# ---- Stage 1: compile the Rust engine as a C-ABI shared library -------------------------
FROM rust:1-slim-bookworm AS rust-builder
WORKDIR /rust
COPY sdp-engine/Cargo.toml sdp-engine/Cargo.lock ./
COPY sdp-engine/src ./src
RUN cargo build --release --lib

# ---- Stage 2: compile the Java API -------------------------------------------------------
FROM maven:3.9-eclipse-temurin-22 AS java-builder
WORKDIR /app
COPY sdp-api/pom.xml ./
COPY sdp-api/src ./src
RUN mvn -B -q clean package -DskipTests

# ---- Stage 3: runtime — JRE + the compiled jar + the compiled .so, nothing else ---------
FROM eclipse-temurin:22-jre-jammy
WORKDIR /app

COPY --from=rust-builder /rust/target/release/libsdp_engine.so /app/lib/libsdp_engine.so
COPY --from=java-builder /app/target/sdp-api-*.jar /app/app.jar

EXPOSE 8080
ENTRYPOINT ["java", "--enable-native-access=ALL-UNNAMED", "-jar", "/app/app.jar"]
