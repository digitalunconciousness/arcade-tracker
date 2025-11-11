{% extends "base.html" %}

{% block content %}
<div class="container mt-4">
  <a href="{{ url_for('maintenance_orders') }}" class="btn btn-link mb-3">&larr; Back to Orders</a>

  <div class="card shadow-sm">
    <div class="card-body">
      <h3 class="card-title mb-2">
        {% if record.game %}
          {{ record.game.name }}
        {% else %}
          General Maintenance
        {% endif %}
      </h3>

      <h6 class="text-muted mb-3">{{ record.work_order_type|capitalize }}</h6>

      <div class="mb-3">
        <span class="badge bg-info text-dark me-2">{{ record.status }}</span>
        <small class="text-muted">Reported on {{ record.date_reported.strftime('%Y-%m-%d') if record.date_reported else 'Unknown' }}</small>
      </div>

      <h5>Issue Description</h5>
      <p>{{ record.issue_description or 'No description provided.' }}</p>

      {% if record.fix_description %}
        <h5>Fix Description</h5>
        <p>{{ record.fix_description }}</p>
      {% endif %}

      {% if record.work_notes %}
        <h5>Work Notes</h5>
        <p>{{ record.work_notes }}</p>
      {% endif %}

      {% if record.parts_used %}
        <h5>Parts Used</h5>
        <p>{{ record.parts_used }}</p>
      {% endif %}

      {% if record.technician %}
        <p class="mt-3"><strong>Technician:</strong> {{ record.technician }}</p>
      {% endif %}
    </div>
  </div>
</div>
{% endblock %}
