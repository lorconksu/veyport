# Rebrand Naming Research Handoff

Date: 2026-05-15
Branch: `feature/terminal-ldap-access`

## Context

The terminal/SSH addition changes the product from a docs/files/logs-focused tool into a lightweight secure bastion and terminal gateway. The working SemVer direction is `v2.0.0`, because the product boundary and positioning changed materially.

The user wants a product name that does not include YiuCloud or the user's name. Desired positioning is roughly "Teleport lite": secure terminal access, bastion gateway, server operations, LDAP-backed identity, auditability, files, and logs.

## Current Naming Direction

The strongest lower-risk shortlist from the last pass:

- `Veyport`: current recommendation. Terminal + guardian. Good security/terminal fit, more distinctive than descriptive names. Quick checks found no npm/PyPI hit and `veyport.net` returned no Verisign RDAP record.
- `BastionDesk`: clear and operator-friendly. More descriptive and weaker as a trademark. One GitHub repo exists with this name for incident management, not terminal gateway.
- `AccessKeep`: broad secure-access framing without `Citadel`. Slightly less obvious. `AccessKeeper` exists as a GitHub repo, so needs more clearance.

Names to avoid from quick screening:

- `ShellKeep`: direct terminal/SSH-session GitHub collisions.
- `ShellGate`: already used for security gateway/SSH-agent access.
- `RelayGate`: already an AI gateway product.
- `Gateward`: already a PyPI security/proxy tool.
- `OpenBastion`: `openbastionai.org` exists in security gateway territory.
- `Gatehouse` and `Keyway`: crowded with existing marks/brands.

## OpenCitadel Research Summary

`OpenCitadel` was liked, and `opencitadel.net` looked thematically strong for a network/terminal application. It is a good meaning fit but not a low-risk trademark path.

Risk classification from the research pass: medium.

Why:

- Exact joined spelling `OpenCitadel` looked sparse in npm, PyPI, Docker Hub, GitHub namespace checks, and search.
- `opencitadel.net` did not appear registered/resolving at the time checked.
- `opencitadel.com` is already registered/listed for sale on Atom.
- `Open Citadel Limited` exists in the UK as an active artistic/media company, so avoid spaced/hyphenated `Open Citadel` / `open-citadel`.
- The word `CITADEL` is crowded in adjacent software/security/network areas.
- Notable adjacent marks/products found:
  - Citadel browser agent: open-source enterprise browser security tool.
  - Switch, Ltd. `CITADEL` mark in telecommunications/internet connectivity.
  - Processing Point `CITADEL` mark in software/hardware for time and attendance.
  - FuriosaAI pending/suspended `CITADEL` application covering broad software terms, including access server applications.
  - Citadel finance brand is famous and claims `Citadel`, `Citadel Securities`, and castle-logo-related marks.

If `OpenCitadel` is used anyway:

- Use exact joined form only: `OpenCitadel`.
- Avoid `Open Citadel`, `open-citadel`, and literal castle logo treatments.
- Prefer abstract gate, terminal prompt, keyway, guarded session, or relay motif.
- Register/reserve `opencitadel.net`, GitHub org/user, Docker Hub, npm, and PyPI quickly.
- Get attorney clearance before a public v2 rebrand.

## Visual Companion Note

The brainstorming companion was run on the mini PC at:

`http://10.10.1.95:60157`

It was started with host binding because the user's PC is on the same network but not on the mini PC, so `localhost` does not work for the user.

Restart command after reboot:

```bash
/home/wyiu/.codex/plugins/cache/openai-curated/superpowers/1b89ff49/skills/brainstorming/scripts/start-server.sh \
  --project-dir /home/wyiu/personal/veyport \
  --host 0.0.0.0 \
  --url-host 10.10.1.95
```

The old companion content was under `.superpowers/brainstorm/3172606-1778792339/`, which is local scratch state.

## Suggested Resume Point

Resume by asking whether to run deeper clearance on `Veyport`, `BastionDesk`, and `AccessKeep`, or whether to keep `OpenCitadel` despite medium risk.
