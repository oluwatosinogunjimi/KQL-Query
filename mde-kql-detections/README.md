# MDE KQL Detection Rules

Personal repository of KQL-based threat hunting queries and custom detection rules for Microsoft Defender for Endpoint (MDE) and Microsoft Defender XDR.

This repository is built to document, refine, and expand a practical detection engineering library aligned with MITRE ATT&CK. The rules are designed for small-to-medium environments and may require environment-specific tuning.

## Structure overview

- `detections/`: Core detections organized by ATT&CK tactic.
- `emerging-threats/`: Detections and hunts for fast-moving tradecraft.
- `tuning/`: Tuning logs and exclusion history.
- `RULE_TEMPLATE.md`: Reusable format for documenting detections.

## How to use

1. Start with a query in Microsoft Defender XDR Advanced Hunting.
2. Validate expected behavior and result quality.
3. Tune for your environment.
4. Promote to a custom detection rule after validation.

## Disclaimer

These queries are starting points. Detection quality depends on environment, telemetry coverage, and operational context, so tuning is expected.
