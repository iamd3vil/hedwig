{% for commit in commits if commit.subject|starts_with("feat") or commit.subject|starts_with("refactor") %}
{%- if loop.first %}
### Features:
{%- endif %}
{{ commit.hash }}: {{ commit.subject|trim("feat: ")|trim("refactor: ") }}
{%- endfor %}

{# Fixes Section: Render header only if fixes exist, using loop.first #}
{% for commit in commits if commit.subject|starts_with("fix") %}
{%- if loop.first %} {# Check if this is the first iteration of *this* loop #}

### Fixes:
{%- endif %}
{{ commit.hash }}: {{ commit.subject }}
{%- endfor %}
