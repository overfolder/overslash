# Licensing

Overslash is a commercial open-source project developed by **Overspiral S.L.**,
a Spanish Sociedad Limitada Unipersonal (SLU). Different parts of the
repository are released under different licenses.

## Summary

| Path | License | Notes |
|------|---------|-------|
| `/` (everything except the exceptions below) | **Elastic License 2.0** | Source available. Free to use, self-host, modify, and use commercially — except you may not offer Overslash as a hosted/managed service to third parties. |
| `services/*.yaml` | **MIT** | Service registry definitions for third-party APIs. Freely reusable, including in proprietary or competing products. |
| `assets/service-icons/` | **No licence granted** | Third-party trademarks, included to identify the vendor products our service templates integrate with. Overspiral S.L. does not own them and cannot sublicense them — see [`assets/service-icons/NOTICE.md`](assets/service-icons/NOTICE.md). |
| SDKs / client libraries | *To be determined* | We expect to release SDKs under a more permissive license (likely Apache-2.0 or MIT). This will be settled before the first SDK release. |

Full license texts:

- Elastic License 2.0 — see [`LICENSE`](LICENSE)
- MIT (service YAMLs) — see [`services/LICENSE`](services/LICENSE)
- Trademark notice (service icons) — see [`assets/service-icons/NOTICE.md`](assets/service-icons/NOTICE.md)

## What you can do under the Elastic License 2.0

- ✅ Use Overslash internally at your company, free of charge
- ✅ Self-host Overslash for your own product or platform
- ✅ Modify the source code and run modified versions
- ✅ Redistribute the source code (modified or unmodified)
- ✅ Build commercial products on top of Overslash

## What you cannot do under the Elastic License 2.0

- ❌ Offer Overslash (or a substantial portion of its features) as a hosted or
  managed service to third parties
- ❌ Circumvent or remove license-key functionality
- ❌ Remove or obscure copyright, license, or trademark notices

If you want to offer a managed Overslash service, contact Overspiral S.L. for
a commercial license.

## Why this split

- The **core** (gateway, vault, permission chain, dashboard) is under ELv2 to
  protect the eventual managed Overslash Cloud offering from being resold by
  third parties, while keeping the software fully usable for self-hosting and
  internal commercial use.
- The **service registry YAMLs** are under MIT because they are declarative
  data describing public third-party APIs. They have no patentable content,
  customers will routinely vendor and edit them, and the ecosystem benefits
  when these definitions can flow freely between projects.
- The **SDKs** will be permissively licensed so customers can embed them in
  any application without legal review.
- The **service icons** are carved out of both licences because they are marks we
  do not own. They are shipped under nominative use — identifying the vendor
  product a template integrates with — and no licence to them travels with this
  repository.

## Contributing

By submitting a contribution to this repository, you agree that your
contribution is licensed under the same license as the file or directory it
applies to (Elastic License 2.0 for code, MIT for `services/*.yaml`), and that
you have the right to submit it under that license.

## Questions

For commercial licensing, partnerships, or any licensing questions, contact
Overspiral S.L.

---

Copyright © 2026 Overspiral S.L. All rights reserved.
