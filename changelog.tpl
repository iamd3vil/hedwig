{% set features = commits | selectattr("type", "equalto", "feat") | list %}
{% set fixes = commits | selectattr("type", "equalto", "fix") | list %}
{% set chores = commits | selectattr("type", "equalto", "chore") | list %}

{% if features | length > 0 %}
### Features:
{% for commit in features %}
{{ commit.hash }}: {{ commit.subject }}{% if commit.handle %} (@{{ commit.handle }}){% endif %}
{%- endfor %}
{% endif %}

{% if fixes | length > 0 %}
### Fixes:
{% for commit in fixes %}
{{ commit.hash }}: {{ commit.subject }}{% if commit.handle %} (@{{ commit.handle }}){% endif %}
{%- endfor %}
{% endif %}

{% if chores | length > 0 %}
### Chores:
{% for commit in chores %}
{{ commit.hash }}: {{ commit.subject }}{% if commit.handle %} (@{{ commit.handle }}){% endif %}
{%- endfor %}
{% endif %}

{% set contributors = [] %}
{% for commit in commits %}
{% if commit.handle and commit.handle not in contributors %}
{% set contributors = contributors + [commit.handle] %}
{% endif %}
{% endfor %}

{% set contributor_counts = [] %}
{% for handle in contributors %}
{% set count = commits | selectattr("handle", "equalto", handle) | list | length %}
{% set contributor_counts = contributor_counts + [{"handle": handle, "count": count}] %}
{% endfor %}
{% set contributor_counts = contributor_counts | sort(attribute="handle") %}
{% set contributor_counts = contributor_counts | sort(attribute="count", reverse=true) %}

{% if contributor_counts | length > 0 %}
### Contributors:
{% for contributor in contributor_counts %}
- @{{ contributor.handle }}
{%- endfor %}
{% endif %}
