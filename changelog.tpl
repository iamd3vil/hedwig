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

{% if contributors | length > 0 %}
### Contributors:
{% for handle in contributors %}
- @{{ handle }}
{%- endfor %}
{% endif %}
