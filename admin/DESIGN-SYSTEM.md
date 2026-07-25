# Axiom Admin UI Design Direction

## Visual Tokens

- Navy is the authority color: use `axiom-*` for shell, primary actions, headers, and selected states.
- Gold is the premium accent: use `gold-*` for focus, active rails, key icons, and small status accents.
- Surfaces use `canvas`, `panel`, `line`, and `ink-*` to keep dense admin pages readable without generic blue-on-white styling.
- `brand-*` aliases the Axiom navy scale so older components inherit the new system while they are migrated.

## Component Direction

- Use `surface-card`, `surface-panel`, `page-shell`, `page-kicker`, `section-heading`, `muted-copy`, and `axiom-mark` from `src/index.css`.
- Keep admin layouts dense: compact headers, 8px card radius, clear tables, and predictable controls.
- Prefer navy primary buttons with gold focus treatment; reserve gold fill for accents, not full-page color blocks.
- Avoid marketing-style hero sections, oversized cards, and decorative graphics in admin workflows.

## Priority Surfaces

- Shell/sidebar establishes the dark navy enterprise frame and active gold rail.
- Login uses the Axiom mark and navy/gold treatment while preserving the existing username/password flow.
- Dashboard stat cards and activity panel set the pattern for future high-density operational pages.
