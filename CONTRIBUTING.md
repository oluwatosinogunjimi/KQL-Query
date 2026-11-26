# Contributing

Thanks for your interest. This is a personal detection library, so contributions are welcome but reviewed against a few rules.

## What gets accepted

- Fixes to query logic, field names or syntax
- False positive or tuning improvements backed by a clear explanation
- New indicators for an existing rule when they are supported by **independent public threat reporting** (vendor security research, government advisories, incident reports)

## What doesn't

- **Vendor-submitted additions.** Pull requests from a vendor, or from someone affiliated with one, that add their own product to a rule, or link to their own site, are closed. This applies even when the product is legitimate. Tools are added to a rule because there is public reporting of threat actors abusing them, not because a vendor asks.
- Vendor links, product references or marketing text in rule write-ups
- Environment-specific details: real hostnames, users, IPs, tenant names, approved-tool lists or production results. The queries here are templates.

## How to contribute

1. Open an issue first describing the change and linking your sources.
2. Keep each pull request to one rule and one change.
3. Follow the format in [RULE_TEMPLATE.md](RULE_TEMPLATE.md), and update the rule's Tuning Notes with the date, change and reason.

By contributing, you agree that your contribution is licensed under the [MIT License](LICENSE).
