package com.openwolf.iam.authority.approval;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.JsonNodeFactory;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

/**
 * Phase 3.7 canonical action form ("axiom-action-v1"), shared contract with receivers:
 *
 * <pre>
 * document = {"action": &lt;action object&gt;, "audience": &lt;receiver audience&gt;, "type": &lt;action type&gt;}
 * canonical = JSON with object keys sorted by Java String order (UTF-16 code units), no insignificant whitespace,
 *             strings escaped as JSON strings, numbers only as integers in the signed 64-bit range
 *             (amounts in minor units or as decimal strings), booleans, arrays in order; no null, no floats
 * digest    = lowercase hex SHA-256 of the UTF-8 canonical bytes
 * </pre>
 *
 * Every field of the action is protected: changing any value (amount, recipient, account, operation, ...) changes the
 * digest and therefore needs a new approval. Free text inside an action is data, never authority.
 */
public final class ActionCanonicalizer {
    public static final String VERSION = "axiom-action-v1";
    static final int MAX_BYTES = 8192;
    static final int MAX_DEPTH = 5;

    private ActionCanonicalizer() {}

    public record Canonical(String json, String digest) {}

    public static Canonical canonicalize(String actionType, String audience, JsonNode action) {
        if (action == null || !action.isObject() || action.isEmpty()) {
            throw new IllegalArgumentException("action must be a non-empty object");
        }
        var document = JsonNodeFactory.instance.objectNode();
        document.set("action", action);
        document.put("audience", audience);
        document.put("type", actionType);
        StringBuilder out = new StringBuilder();
        write(document, out, 0);
        String json = out.toString();
        byte[] bytes = json.getBytes(StandardCharsets.UTF_8);
        if (bytes.length > MAX_BYTES) throw new IllegalArgumentException("action is too large");
        return new Canonical(json, digest(bytes));
    }

    private static void write(JsonNode node, StringBuilder out, int depth) {
        if (depth > MAX_DEPTH) throw new IllegalArgumentException("action is nested too deeply");
        if (node.isObject()) {
            List<String> keys = new ArrayList<>();
            Iterator<Map.Entry<String, JsonNode>> fields = node.fields();
            while (fields.hasNext()) keys.add(fields.next().getKey());
            keys.sort(String::compareTo);
            out.append('{');
            for (int i = 0; i < keys.size(); i++) {
                if (i > 0) out.append(',');
                out.append(JsonNodeFactory.instance.textNode(keys.get(i)).toString()).append(':');
                write(node.get(keys.get(i)), out, depth + 1);
            }
            out.append('}');
        } else if (node.isArray()) {
            out.append('[');
            for (int i = 0; i < node.size(); i++) {
                if (i > 0) out.append(',');
                write(node.get(i), out, depth + 1);
            }
            out.append(']');
        } else if (node.isTextual()) {
            out.append(node.toString());
        } else if (node.isIntegralNumber() && node.canConvertToLong()) {
            out.append(node.asLong());
        } else if (node.isBoolean()) {
            out.append(node.asBoolean());
        } else {
            throw new IllegalArgumentException("action values must be strings, integers, booleans, objects or arrays");
        }
    }

    static String digest(byte[] bytes) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes));
        } catch (Exception e) {
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
    }
}
