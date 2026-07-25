package com.openwolf.iam.policystudio;

import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * A deliberately tight evaluator for the CEL subset that Cerbos conditions in the generated
 * tenant-restriction shape actually use (Axiom Story C3). It is used by
 * {@link PolicyExpectationEvaluator} to decide whether a candidate rule's condition holds for a given
 * probe's attributes, so the independent oracle can tell ALLOW from DENY without a live PDP for the
 * reproducible, in-process catch-rate harness.
 *
 * <p><b>Supported</b>: {@code P.attr.<x>} / {@code R.attr.<x>} references, string / boolean / list
 * literals, {@code ==}, {@code !=}, {@code in}, {@code &&}, {@code ||}, parentheses, and
 * {@code has(<ref>)}. <b>Everything else throws {@link UnsupportedConditionException}</b> — the
 * evaluator never guesses. A caller that gets that exception must treat the policy decision as
 * <em>indeterminate</em> for that rule (and the catch-rate harness records the item as not
 * oracle-decidable rather than silently claiming a catch).
 *
 * <p><b>Missing-attribute semantics (the important one):</b> referencing an absent attribute inside a
 * comparison raises {@link ConditionErrorException} — mirroring Cerbos, where evaluating a condition
 * against a missing attribute errors and the rule does not match. {@code has(ref)} is the guard that
 * lets a well-written policy check presence first; {@code &&} short-circuits so
 * {@code has(x) && x == y} is false (not an error) when {@code x} is absent. A policy that omits the
 * {@code has()} guard therefore errors on the missing-attribute probe and fails to ALLOW — which is
 * the fail-closed behaviour the probe demands.
 */
@Component
public class ConditionEvaluator {

    /** Thrown when a condition uses a construct outside the supported subset. */
    public static class UnsupportedConditionException extends RuntimeException {
        public UnsupportedConditionException(String message) {
            super(message);
        }
    }

    /** Thrown when a comparison touches a missing attribute (Cerbos would error → rule non-match). */
    public static class ConditionErrorException extends RuntimeException {
        public ConditionErrorException(String message) {
            super(message);
        }
    }

    /** Sentinel for an absent attribute reference. */
    private static final Object MISSING = new Object();

    /**
     * Evaluate {@code expr} against the environment (keys like {@code "R.attr.data_classification"} →
     * {@code String}/{@code Boolean}; absent key ⇒ missing).
     *
     * @return whether the condition holds
     * @throws UnsupportedConditionException on an unsupported construct
     * @throws ConditionErrorException       on a missing attribute inside a comparison
     */
    public boolean evaluate(String expr, Map<String, Object> env) {
        List<String> tokens = tokenize(expr);
        Parser parser = new Parser(tokens);
        Node ast = parser.parseOr();
        parser.expectEnd();
        return ast.eval(env);
    }

    // ── tokenizer ──────────────────────────────────────────────────────────────────────────────

    private static List<String> tokenize(String expr) {
        List<String> out = new ArrayList<>();
        int i = 0;
        int n = expr.length();
        while (i < n) {
            char c = expr.charAt(i);
            if (Character.isWhitespace(c)) {
                i++;
            } else if (c == '"' || c == '\'') {
                int j = i + 1;
                StringBuilder sb = new StringBuilder("\"");
                while (j < n && expr.charAt(j) != c) {
                    sb.append(expr.charAt(j));
                    j++;
                }
                if (j >= n) {
                    throw new UnsupportedConditionException("unterminated string literal in: " + expr);
                }
                sb.append('"');
                out.add(sb.toString());
                i = j + 1;
            } else if (c == '(' || c == ')' || c == '[' || c == ']' || c == ',') {
                out.add(String.valueOf(c));
                i++;
            } else if (expr.startsWith("==", i) || expr.startsWith("!=", i)
                    || expr.startsWith("&&", i) || expr.startsWith("||", i)) {
                out.add(expr.substring(i, i + 2));
                i += 2;
            } else if (isIdentChar(c)) {
                int j = i;
                while (j < n && (isIdentChar(expr.charAt(j)) || expr.charAt(j) == '.' || expr.charAt(j) == '-')) {
                    j++;
                }
                out.add(expr.substring(i, j));
                i = j;
            } else {
                throw new UnsupportedConditionException("unsupported character '" + c + "' in: " + expr);
            }
        }
        return out;
    }

    private static boolean isIdentChar(char c) {
        return Character.isLetterOrDigit(c) || c == '_';
    }

    // ── AST ────────────────────────────────────────────────────────────────────────────────────

    private interface Node {
        boolean eval(Map<String, Object> env);
    }

    private static Object resolve(String ref, Map<String, Object> env) {
        if (ref.equals("true")) {
            return Boolean.TRUE;
        }
        if (ref.equals("false")) {
            return Boolean.FALSE;
        }
        if (ref.startsWith("P.attr.") || ref.startsWith("R.attr.")) {
            return env.containsKey(ref) ? env.get(ref) : MISSING;
        }
        throw new UnsupportedConditionException("unsupported reference '" + ref + "'");
    }

    // ── parser (recursive descent) ───────────────────────────────────────────────────────────────

    private static final class Parser {
        private final List<String> t;
        private int p;

        Parser(List<String> tokens) {
            this.t = tokens;
        }

        private String peek() {
            return p < t.size() ? t.get(p) : null;
        }

        private String next() {
            return t.get(p++);
        }

        void expectEnd() {
            if (p != t.size()) {
                throw new UnsupportedConditionException("trailing tokens from position " + p + ": " + t);
            }
        }

        Node parseOr() {
            Node left = parseAnd();
            while ("||".equals(peek())) {
                next();
                Node right = parseAnd();
                Node l = left;
                left = env -> l.eval(env) || right.eval(env);
            }
            return left;
        }

        Node parseAnd() {
            Node left = parseComparison();
            while ("&&".equals(peek())) {
                next();
                Node right = parseComparison();
                Node l = left;
                left = env -> l.eval(env) && right.eval(env); // short-circuit → guards work
            }
            return left;
        }

        Node parseComparison() {
            if ("(".equals(peek())) {
                next();
                Node inner = parseOr();
                if (!")".equals(peek())) {
                    throw new UnsupportedConditionException("expected ')' in condition");
                }
                next();
                return inner;
            }
            String tok = peek();
            if (tok == null) {
                throw new UnsupportedConditionException("unexpected end of condition");
            }
            if ("has".equals(tok)) {
                return parseHas();
            }
            // operand OP operand  (or a bare boolean reference)
            Operand left = parseOperand();
            String op = peek();
            if ("==".equals(op) || "!=".equals(op) || "in".equals(op)) {
                next();
                Operand right = parseOperand();
                boolean eq = "==".equals(op);
                boolean isIn = "in".equals(op);
                return env -> {
                    if (isIn) {
                        Object lv = left.value(env);
                        Object rv = right.value(env);
                        if (lv == MISSING) {
                            throw new ConditionErrorException("missing attribute on left of 'in'");
                        }
                        if (!(rv instanceof List<?> list)) {
                            throw new UnsupportedConditionException("'in' right operand is not a list");
                        }
                        return list.contains(lv);
                    }
                    Object lv = left.value(env);
                    Object rv = right.value(env);
                    if (lv == MISSING || rv == MISSING) {
                        throw new ConditionErrorException("comparison touches a missing attribute");
                    }
                    boolean equal = lv.equals(rv);
                    return eq == equal;
                };
            }
            // bare boolean operand (e.g. a boolean attribute or literal true)
            return env -> {
                Object v = left.value(env);
                if (v == MISSING) {
                    throw new ConditionErrorException("bare reference is a missing attribute");
                }
                if (v instanceof Boolean b) {
                    return b;
                }
                throw new UnsupportedConditionException("bare non-boolean operand");
            };
        }

        Node parseHas() {
            next(); // 'has'
            if (!"(".equals(peek())) {
                throw new UnsupportedConditionException("expected '(' after has");
            }
            next();
            String ref = next();
            if (!")".equals(peek())) {
                throw new UnsupportedConditionException("expected ')' after has(<ref>)");
            }
            next();
            if (!(ref.startsWith("P.attr.") || ref.startsWith("R.attr."))) {
                throw new UnsupportedConditionException("has() must guard an attribute reference");
            }
            return env -> env.containsKey(ref) && env.get(ref) != null;
        }

        Operand parseOperand() {
            String tok = next();
            if (tok.startsWith("\"")) {
                String lit = tok.substring(1, tok.length() - 1);
                return env -> lit;
            }
            if ("[".equals(tok)) {
                List<String> items = new ArrayList<>();
                while (!"]".equals(peek())) {
                    String item = next();
                    if (!item.startsWith("\"")) {
                        throw new UnsupportedConditionException("list literals must contain string literals");
                    }
                    items.add(item.substring(1, item.length() - 1));
                    if (",".equals(peek())) {
                        next();
                    }
                }
                next(); // ']'
                return env -> items;
            }
            String ref = tok;
            return env -> resolve(ref, env);
        }
    }

    private interface Operand {
        Object value(Map<String, Object> env);
    }
}
