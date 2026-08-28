<!-- converted from test_p_loop.docx -->

# {{ title }}
{% for item in items %}🔹 {{ item.name }}: {{ item.desc }}
Status: {{ item.status }}
{% endfor %}