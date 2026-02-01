---
layout: ../layouts/DocLayout.astro
title: Domain filtering
description: Filter inbound mail by sender or recipient domain.
---

# Domain filtering

```toml
[[filters]]
type = "from_domain_filter"              # from_domain_filter or to_domain_filter
domain = ["allowed1.com", "allowed2.com"]
action = "allow"                         # allow or deny

[[filters]]
type = "to_domain_filter"
domain = ["spam.com", "blocked.com"]
action = "deny"
```
