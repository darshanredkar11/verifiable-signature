package com.sdp.api;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;

import java.io.IOException;
import java.util.List;
import java.util.UUID;

/**
 * REST facade over the SDP-1 Rust engine. Every endpoint below calls straight into the
 * real, independently-tested Rust cdylib via {@link RustEngine} (JDK 22 Foreign
 * Function & Memory API, in-process, no subprocess, no temp files) — Rust is the sole
 * trust boundary that performs canonicalization, hashing, Merkle tree construction,
 * Ed25519 signing, and semantic delta classification. This controller does not
 * reimplement any of that logic in Java; it only marshals JSON in and out and fails
 * closed if the native call errors, rather than fabricating a result.
 */
@Tag(name = "Semantic Delta Proof Engine", description = "Endpoints for document commitment, semantic delta verification, and evidence extraction")
@RestController
@RequestMapping("/api/sdp")
@CrossOrigin(origins = "*")
public class SdpController {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private static final String DEFAULT_SCHEMA_JSON = "["
            + "{\"fieldName\":\"tenant\",\"displayName\":\"Tenant\",\"criticality\":\"normal\",\"valueType\":\"text\"},"
            + "{\"fieldName\":\"landlord\",\"displayName\":\"Landlord\",\"criticality\":\"normal\",\"valueType\":\"text\"},"
            + "{\"fieldName\":\"rent\",\"displayName\":\"Monthly Rent\",\"criticality\":\"critical\",\"valueType\":\"currency\"},"
            + "{\"fieldName\":\"deposit\",\"displayName\":\"Security Deposit\",\"criticality\":\"normal\",\"valueType\":\"currency\"},"
            + "{\"fieldName\":\"startDate\",\"displayName\":\"Lease Start Date\",\"criticality\":\"normal\",\"valueType\":\"date\"}"
            + "]";

    // ---- COMMAND 1: Commit original document ------------------------------------------

    @Operation(summary = "Commit a Document", description = "Extracts claims per schema, builds Merkle tree, and produces signed Ed25519 semantic commitment.")
    @PostMapping("/commit")
    public JsonNode commitDocument(@RequestBody CommitRequest request) throws IOException {
        String keypairJson = RustEngine.generateKeypair();
        String privateKeyHex = parseEngineJson(keypairJson).path("privateKeyHex").asText();

        String docJson = MAPPER.writeValueAsString(request.getDocument());
        String schemaJson = MAPPER.writeValueAsString(schemaOrDefault(request.getSchema()));

        String commitOutput = RustEngine.commit(docJson, schemaJson, privateKeyHex, "1.0");
        JsonNode commitment = parseEngineJson(commitOutput);

        ObjectNode result = MAPPER.createObjectNode();
        result.put("status", "COMMITTED");
        result.set("commitment", commitment);
        return result;
    }

    // ---- COMMAND 2/3/4: Verify a representation against an original commitment --------

    @Operation(summary = "Verify Unchanged Document", description = "Checks byte-level and semantic integrity against an original commitment.")
    @PostMapping("/verify-unchanged")
    public JsonNode verifyUnchanged(@RequestBody VerifyRequest request) throws Exception {
        return runVerify(request.getDocument(), request.getSchema(), request.getOriginalCommitment());
    }

    @Operation(summary = "Verify Reformatted Document", description = "Verifies semantically equivalent documents (e.g. PDF/A, OCR, currency symbol vs code, date formatting).")
    @PostMapping("/verify-reformatted")
    public JsonNode verifyReformatted(@RequestBody VerifyRequest request) throws Exception {
        return runVerify(request.getDocument(), request.getSchema(), request.getOriginalCommitment());
    }

    @Operation(summary = "Verify Modified Document", description = "Detects critical/semantic changes and generates per-claim Merkle inclusion proof cryptographic evidence.")
    @PostMapping("/verify-modified")
    public JsonNode verifyModified(@RequestBody ModifiedRequest request) throws Exception {
        return runVerify(request.getDocument(), request.getSchema(), request.getOriginalCommitment());
    }

    // ---- COMMAND 5: Tamper with a single field and classify the result ----------------

    @Operation(summary = "Tamper Field Test", description = "Mutates a single field of the original document (format/metadata/date) and verifies the real classification.")
    @PostMapping("/tamper-field")
    public JsonNode tamperField(@RequestBody TamperRequest request) throws Exception {
        JsonNode original = request.getOriginalDocument();
        ObjectNode doc = original != null ? original.deepCopy() : MAPPER.createObjectNode();

        String field = request.getField() != null ? request.getField() : "";
        if ("date".equals(field)) {
            // Same calendar date, different textual representation — format-only by construction.
            JsonNode start = doc.get("startDate") != null ? doc.get("startDate") : doc.get("start");
            String reformatted = reformatDate(start != null ? start.asText() : "2026-09-01");
            if (doc.has("startDate")) doc.put("startDate", reformatted);
            else doc.put("start", reformatted);
        } else if ("format".equals(field) && doc.has("rent")) {
            doc.put("rent", reformatCurrency(doc.get("rent").asText()));
        } else if ("metadata".equals(field)) {
            doc.put("_metadataRevision", UUID.randomUUID().toString());
        }

        return runVerify(doc, request.getSchema(), request.getOriginalCommitment());
    }

    // ---- shared verify path -------------------------------------------------------------

    private JsonNode runVerify(JsonNode document, Object schema, Object originalCommitment) throws IOException {
        if (originalCommitment == null) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "originalCommitment is required — call /api/sdp/commit first");
        }

        String docJson = MAPPER.writeValueAsString(document);
        String schemaJson = MAPPER.writeValueAsString(schemaOrDefault(schema));
        String commitmentJson = MAPPER.writeValueAsString(originalCommitment);

        String output = RustEngine.verify(docJson, schemaJson, commitmentJson);
        JsonNode proof = parseEngineJson(output);

        boolean bytePass = proof.path("byteIntegrity").path("passed").asBoolean(false);
        boolean semPass = proof.path("semanticIntegrity").path("passed").asBoolean(false);
        String classification = proof.path("status").asText("UNKNOWN");

        ObjectNode result = MAPPER.createObjectNode();
        result.put("byteIntegrity", bytePass ? "PASS" : "FAIL");
        result.put("semanticIntegrity", semPass ? "PASS" : "FAIL");
        result.put("classification", classification);
        result.put("result", classification);
        result.put("originalCommitmentValid", proof.path("originalCommitmentValid").asBoolean(false));
        result.set("changes", proof.path("changes"));

        ObjectNode evidence = MAPPER.createObjectNode();
        evidence.set("originalCommitment", proof.path("originalCommitment"));
        evidence.put("currentCommitment", proof.path("currentCommitment").asText(""));
        evidence.set("changes", proof.path("changes"));
        result.set("evidence", evidence);

        return result;
    }

    // ---- engine call plumbing ------------------------------------------------------------

    private JsonNode parseEngineJson(String output) throws IOException {
        JsonNode node = MAPPER.readTree(output);
        if (node.has("error")) {
            throw new ResponseStatusException(HttpStatus.UNPROCESSABLE_ENTITY, node.get("error").asText());
        }
        return node;
    }

    private JsonNode schemaOrDefault(Object schema) throws IOException {
        if (schema == null) return MAPPER.readTree(DEFAULT_SCHEMA_JSON);
        return MAPPER.valueToTree(schema);
    }

    private static String reformatDate(String iso) {
        // "2026-09-01" -> "September 1, 2026" (same calendar date, different text — format-only).
        String[] months = {"January", "February", "March", "April", "May", "June", "July",
                "August", "September", "October", "November", "December"};
        try {
            String[] parts = iso.split("-");
            int y = Integer.parseInt(parts[0]);
            int m = Integer.parseInt(parts[1]);
            int d = Integer.parseInt(parts[2]);
            return months[m - 1] + " " + d + ", " + y;
        } catch (Exception e) {
            return iso;
        }
    }

    private static String reformatCurrency(String value) {
        // "€1,500" -> "1500.00 EUR" style, or vice versa — same amount, different notation.
        String digits = value.replaceAll("[^0-9.]", "");
        if (value.contains("EUR") || value.contains("€")) {
            return "EUR " + digits;
        }
        return "€" + digits;
    }

    // ---- Request DTOs -------------------------------------------------------------------

    public static class CommitRequest {
        private JsonNode document;
        private List<ClaimSchema> schema;

        public JsonNode getDocument() { return document; }
        public void setDocument(JsonNode document) { this.document = document; }
        public List<ClaimSchema> getSchema() { return schema; }
        public void setSchema(List<ClaimSchema> schema) { this.schema = schema; }
    }

    public static class ClaimSchema {
        private String fieldName;
        private String displayName;
        private String criticality;
        private String valueType;

        public String getFieldName() { return fieldName; }
        public void setFieldName(String fieldName) { this.fieldName = fieldName; }
        public String getDisplayName() { return displayName; }
        public void setDisplayName(String displayName) { this.displayName = displayName; }
        public String getCriticality() { return criticality; }
        public void setCriticality(String criticality) { this.criticality = criticality; }
        public String getValueType() { return valueType; }
        public void setValueType(String valueType) { this.valueType = valueType; }
    }

    public static class VerifyRequest {
        private JsonNode document;
        private Object originalCommitment;
        private Object schema;

        public JsonNode getDocument() { return document; }
        public void setDocument(JsonNode document) { this.document = document; }
        public Object getOriginalCommitment() { return originalCommitment; }
        public void setOriginalCommitment(Object originalCommitment) { this.originalCommitment = originalCommitment; }
        public Object getSchema() { return schema; }
        public void setSchema(Object schema) { this.schema = schema; }
    }

    public static class ModifiedRequest {
        private JsonNode document;
        private Object originalCommitment;
        private Object schema;
        private String changeType;
        private String newValue;

        public JsonNode getDocument() { return document; }
        public void setDocument(JsonNode document) { this.document = document; }
        public Object getOriginalCommitment() { return originalCommitment; }
        public void setOriginalCommitment(Object originalCommitment) { this.originalCommitment = originalCommitment; }
        public Object getSchema() { return schema; }
        public void setSchema(Object schema) { this.schema = schema; }
        public String getChangeType() { return changeType; }
        public void setChangeType(String changeType) { this.changeType = changeType; }
        public String getNewValue() { return newValue; }
        public void setNewValue(String newValue) { this.newValue = newValue; }
    }

    public static class TamperRequest {
        private JsonNode originalDocument;
        private Object originalCommitment;
        private Object schema;
        private String field;

        public JsonNode getOriginalDocument() { return originalDocument; }
        public void setOriginalDocument(JsonNode originalDocument) { this.originalDocument = originalDocument; }
        public Object getOriginalCommitment() { return originalCommitment; }
        public void setOriginalCommitment(Object originalCommitment) { this.originalCommitment = originalCommitment; }
        public Object getSchema() { return schema; }
        public void setSchema(Object schema) { this.schema = schema; }
        public String getField() { return field; }
        public void setField(String field) { this.field = field; }
    }
}
