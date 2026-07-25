package com.openwolf.iam.policystudio;

import org.springframework.stereotype.Component;
import org.yaml.snakeyaml.LoaderOptions;
import org.yaml.snakeyaml.Yaml;
import org.yaml.snakeyaml.constructor.SafeConstructor;
import org.yaml.snakeyaml.events.AliasEvent;
import org.yaml.snakeyaml.events.CollectionStartEvent;
import org.yaml.snakeyaml.events.Event;
import org.yaml.snakeyaml.events.ScalarEvent;

import java.io.StringReader;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Lowers a model's proposed YAML text into the closed, typed {@link PolicyIR} (Axiom Story C2) —
 * the first half of "the parser is the control". It is deliberately strict and fail-closed:
 *
 * <ul>
 *   <li><b>No aliases/anchors</b> — a YAML {@code &anchor}/{@code *alias} is an aliasing vector
 *       (e.g. reusing a "tenant B" block by reference) and is rejected outright.</li>
 *   <li><b>No custom/explicit non-core tags</b> — {@code !!python/...}, {@code !whatever} are
 *       rejected; only the YAML core schema is allowed.</li>
 *   <li><b>Only the resource-policy shape</b> — a single document that is a Cerbos
 *       {@code resourcePolicy}. Any {@code derivedRoles} / {@code principalPolicy} /
 *       {@code rolePolicy} document (which could redefine the trusted derived-role modules or
 *       grant by principal) is rejected.</li>
 *   <li><b>SafeConstructor</b> — never instantiates arbitrary Java types.</li>
 * </ul>
 *
 * Anything it cannot represent, it refuses — it never "best-effort" coerces.
 */
@Component
public class PolicyYamlParser {

    /** YAML 1.1 core-schema tags. Any explicit tag outside this set is a custom tag → rejected. */
    private static final Set<String> ALLOWED_TAGS = Set.of(
            "tag:yaml.org,2002:map",
            "tag:yaml.org,2002:seq",
            "tag:yaml.org,2002:str",
            "tag:yaml.org,2002:int",
            "tag:yaml.org,2002:float",
            "tag:yaml.org,2002:bool",
            "tag:yaml.org,2002:null");

    private static final Set<String> DISALLOWED_TOP_LEVEL = Set.of(
            "derivedRoles", "principalPolicy", "rolePolicy", "exportVariables", "exportConstants");

    /**
     * @throws PolicyParseException on any malformed, aliased, custom-tagged, or non-resource-policy
     *                              input.
     */
    public PolicyIR parse(String yamlText) {
        if (yamlText == null || yamlText.isBlank()) {
            throw new PolicyParseException("empty policy proposal");
        }
        rejectAliasesAndCustomTags(yamlText);

        Object root = safeLoad(yamlText);
        if (!(root instanceof Map<?, ?> doc)) {
            throw new PolicyParseException("top-level YAML must be a mapping");
        }

        for (String forbidden : DISALLOWED_TOP_LEVEL) {
            if (doc.containsKey(forbidden)) {
                throw new PolicyParseException(
                        "only a single 'resourcePolicy' document is allowed; found '" + forbidden + "'");
            }
        }
        if (!doc.containsKey("resourcePolicy")) {
            throw new PolicyParseException("missing 'resourcePolicy' block");
        }
        if (!(doc.get("resourcePolicy") instanceof Map<?, ?> rp)) {
            throw new PolicyParseException("'resourcePolicy' must be a mapping");
        }

        String apiVersion = asString(doc.get("apiVersion"));
        String version = asString(rp.get("version"));
        String resource = asString(rp.get("resource"));
        String scope = rp.get("scope") == null ? "" : asString(rp.get("scope"));
        String scopePermissions = rp.get("scopePermissions") == null ? null : asString(rp.get("scopePermissions"));
        List<String> imports = asStringList(rp.get("importDerivedRoles"));

        List<PolicyIR.Rule> rules = new ArrayList<>();
        Object rawRules = rp.get("rules");
        if (rawRules != null) {
            if (!(rawRules instanceof List<?> ruleList)) {
                throw new PolicyParseException("'rules' must be a sequence");
            }
            for (Object r : ruleList) {
                if (!(r instanceof Map<?, ?> ruleMap)) {
                    throw new PolicyParseException("each rule must be a mapping");
                }
                rules.add(new PolicyIR.Rule(
                        asStringList(ruleMap.get("actions")),
                        asString(ruleMap.get("effect")),
                        asStringList(ruleMap.get("roles")),
                        asStringList(ruleMap.get("derivedRoles")),
                        ruleMap.get("condition")));
            }
        }

        return new PolicyIR(apiVersion, version, resource, scope, scopePermissions, imports, rules);
    }

    // ── alias / custom-tag rejection via the event stream ────────────────────────────────────

    private void rejectAliasesAndCustomTags(String yamlText) {
        LoaderOptions opts = strictLoaderOptions();
        Yaml yaml = new Yaml(new SafeConstructor(opts));
        try {
            for (Event ev : yaml.parse(new StringReader(yamlText))) {
                if (ev instanceof AliasEvent) {
                    throw new PolicyParseException("YAML aliases/anchors are not permitted in a policy proposal");
                }
                if (ev instanceof CollectionStartEvent c) {
                    rejectTag(c.getTag());
                } else if (ev instanceof ScalarEvent s) {
                    rejectTag(s.getTag());
                }
            }
        } catch (PolicyParseException e) {
            throw e;
        } catch (RuntimeException e) {
            throw new PolicyParseException("malformed YAML: " + e.getMessage(), e);
        }
    }

    private void rejectTag(String tag) {
        if (tag != null && !ALLOWED_TAGS.contains(tag)) {
            throw new PolicyParseException("custom/explicit YAML tag '" + tag + "' is not permitted");
        }
    }

    private Object safeLoad(String yamlText) {
        try {
            Yaml yaml = new Yaml(new SafeConstructor(strictLoaderOptions()));
            return yaml.load(yamlText);
        } catch (PolicyParseException e) {
            throw e;
        } catch (RuntimeException e) {
            throw new PolicyParseException("malformed YAML: " + e.getMessage(), e);
        }
    }

    private LoaderOptions strictLoaderOptions() {
        LoaderOptions opts = new LoaderOptions();
        opts.setAllowDuplicateKeys(false);   // duplicate keys are ambiguous → reject
        opts.setAllowRecursiveKeys(false);
        opts.setMaxAliasesForCollections(0); // belt-and-braces: no alias expansion
        opts.setProcessComments(false);
        return opts;
    }

    // ── coercion helpers (fail-closed) ───────────────────────────────────────────────────────

    private static String asString(Object o) {
        if (o == null) {
            return null;
        }
        if (o instanceof String s) {
            return s;
        }
        if (o instanceof Number || o instanceof Boolean) {
            return String.valueOf(o);
        }
        throw new PolicyParseException("expected a scalar string, got " + o.getClass().getSimpleName());
    }

    private static List<String> asStringList(Object o) {
        if (o == null) {
            return List.of();
        }
        if (!(o instanceof List<?> list)) {
            throw new PolicyParseException("expected a sequence, got " + o.getClass().getSimpleName());
        }
        List<String> out = new ArrayList<>(list.size());
        for (Object item : list) {
            out.add(asString(item));
        }
        return out;
    }
}
