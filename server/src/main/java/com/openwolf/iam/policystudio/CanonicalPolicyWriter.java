package com.openwolf.iam.policystudio;

import org.springframework.stereotype.Component;
import org.yaml.snakeyaml.DumperOptions;
import org.yaml.snakeyaml.Yaml;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Materialises CANONICAL YAML from a validated {@link PolicyIR} (Axiom Story C2). We store this,
 * never the model's raw text: the stored artifact is a deterministic re-emission of the fields the
 * gate actually validated, so nothing the model wrote outside the IR (stray keys, comments,
 * formatting tricks) can survive into the policy store. Same IR in ⇒ byte-identical YAML out.
 */
@Component
public class CanonicalPolicyWriter {

    public String write(PolicyIR ir) {
        Map<String, Object> doc = new LinkedHashMap<>();
        doc.put("apiVersion", ir.apiVersion());

        Map<String, Object> rp = new LinkedHashMap<>();
        if (ir.version() != null) {
            rp.put("version", ir.version());
        }
        rp.put("resource", ir.resource());
        rp.put("scope", ir.scope() == null ? "" : ir.scope());
        if (ir.scopePermissions() != null) {
            rp.put("scopePermissions", ir.scopePermissions());
        }
        if (!ir.importDerivedRoles().isEmpty()) {
            rp.put("importDerivedRoles", new ArrayList<>(ir.importDerivedRoles()));
        }

        List<Map<String, Object>> rules = new ArrayList<>();
        for (PolicyIR.Rule rule : ir.rules()) {
            Map<String, Object> r = new LinkedHashMap<>();
            r.put("actions", new ArrayList<>(rule.actions()));
            r.put("effect", rule.effect());
            if (!rule.roles().isEmpty()) {
                r.put("roles", new ArrayList<>(rule.roles()));
            }
            if (!rule.derivedRoles().isEmpty()) {
                r.put("derivedRoles", new ArrayList<>(rule.derivedRoles()));
            }
            if (rule.condition() != null) {
                r.put("condition", rule.condition());
            }
            rules.add(r);
        }
        rp.put("rules", rules);
        doc.put("resourcePolicy", rp);

        DumperOptions opts = new DumperOptions();
        opts.setDefaultFlowStyle(DumperOptions.FlowStyle.BLOCK);
        opts.setIndent(2);
        opts.setPrettyFlow(true);
        opts.setLineBreak(DumperOptions.LineBreak.UNIX);
        opts.setSplitLines(false); // keep CEL expressions on one line (parity with the equality lint)
        return new Yaml(opts).dump(doc);
    }
}
