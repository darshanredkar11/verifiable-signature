package com.sdp.api;

import java.lang.foreign.Arena;
import java.lang.foreign.FunctionDescriptor;
import java.lang.foreign.Linker;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.SymbolLookup;
import java.lang.foreign.ValueLayout;
import java.lang.invoke.MethodHandle;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;

/**
 * Direct in-process foreign-function binding to the sdp-engine Rust cdylib — this is
 * the sole trust boundary: every byte of canonicalization, hashing, Merkle tree
 * construction, Ed25519 signing, and semantic delta classification happens inside the
 * Rust library. Java never re-implements or re-derives any of that logic; it only
 * marshals UTF-8 JSON strings across the FFI boundary using the JDK 22 Foreign
 * Function & Memory API (java.lang.foreign, stable since JDK 22 — no subprocess, no
 * temp files, no JNI glue code).
 *
 * Memory contract: every `sdp_*` native call below returns a heap pointer owned by
 * Rust. It is read once via {@link MemorySegment#getString(long)} and then always
 * released with `sdp_free_string` in the same call — see {@link #readAndFree}.
 */
final class RustEngine {

    private static final long MAX_RESULT_BYTES = 8L * 1024 * 1024;

    private static final Linker LINKER = Linker.nativeLinker();
    private static final MethodHandle GENERATE_KEYPAIR;
    private static final MethodHandle COMMIT;
    private static final MethodHandle VERIFY;
    private static final MethodHandle FREE_STRING;

    static {
        Path libPath = resolveLibraryPath();
        Arena libraryArena = Arena.ofShared(); // library stays mapped for the JVM's lifetime
        SymbolLookup lookup = SymbolLookup.libraryLookup(libPath, libraryArena);

        GENERATE_KEYPAIR = LINKER.downcallHandle(
                lookup.find("sdp_generate_keypair").orElseThrow(() -> missingSymbol("sdp_generate_keypair")),
                FunctionDescriptor.of(ValueLayout.ADDRESS));

        COMMIT = LINKER.downcallHandle(
                lookup.find("sdp_commit").orElseThrow(() -> missingSymbol("sdp_commit")),
                FunctionDescriptor.of(ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.ADDRESS));

        VERIFY = LINKER.downcallHandle(
                lookup.find("sdp_verify").orElseThrow(() -> missingSymbol("sdp_verify")),
                FunctionDescriptor.of(ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.ADDRESS));

        FREE_STRING = LINKER.downcallHandle(
                lookup.find("sdp_free_string").orElseThrow(() -> missingSymbol("sdp_free_string")),
                FunctionDescriptor.ofVoid(ValueLayout.ADDRESS));
    }

    private RustEngine() {}

    private static IllegalStateException missingSymbol(String symbol) {
        return new IllegalStateException("sdp-engine native library is missing expected symbol: " + symbol);
    }

    private static Path resolveLibraryPath() {
        String override = System.getProperty("sdp.engine.lib");
        if (override != null) return Path.of(override);

        String os = System.getProperty("os.name", "").toLowerCase();
        String fileName = os.contains("mac") ? "libsdp_engine.dylib"
                : os.contains("win") ? "sdp_engine.dll"
                : "libsdp_engine.so";

        Path[] candidates = {
                Path.of("sdp-engine/target/release/" + fileName),
                Path.of("/app/lib/" + fileName),
                Path.of(fileName),
        };
        for (Path p : candidates) {
            if (Files.exists(p)) return p.toAbsolutePath();
        }
        throw new IllegalStateException(
                "sdp-engine native library not found (tried " + Arrays.toString(candidates) + "). "
                        + "Build it with: cd sdp-engine && cargo build --release");
    }

    static String generateKeypair() {
        try {
            MemorySegment result = (MemorySegment) GENERATE_KEYPAIR.invokeExact();
            return readAndFree(result);
        } catch (Throwable t) {
            throw new RuntimeException("sdp_generate_keypair FFI call failed", t);
        }
    }

    static String commit(String docJson, String schemaJson, String privateKeyHex, String schemaVersion) {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment doc = arena.allocateFrom(docJson);
            MemorySegment schema = arena.allocateFrom(schemaJson);
            MemorySegment privKey = arena.allocateFrom(privateKeyHex);
            MemorySegment version = arena.allocateFrom(schemaVersion);
            MemorySegment result = (MemorySegment) COMMIT.invokeExact(doc, schema, privKey, version);
            return readAndFree(result);
        } catch (Throwable t) {
            throw new RuntimeException("sdp_commit FFI call failed", t);
        }
    }

    static String verify(String docJson, String schemaJson, String commitmentJson) {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment doc = arena.allocateFrom(docJson);
            MemorySegment schema = arena.allocateFrom(schemaJson);
            MemorySegment commitment = arena.allocateFrom(commitmentJson);
            MemorySegment result = (MemorySegment) VERIFY.invokeExact(doc, schema, commitment);
            return readAndFree(result);
        } catch (Throwable t) {
            throw new RuntimeException("sdp_verify FFI call failed", t);
        }
    }

    private static String readAndFree(MemorySegment resultPtr) throws Throwable {
        MemorySegment sized = resultPtr.reinterpret(MAX_RESULT_BYTES);
        String json = sized.getString(0);
        FREE_STRING.invokeExact(resultPtr);
        return json;
    }
}
