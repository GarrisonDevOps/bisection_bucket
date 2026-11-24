# frozen_string_literal: true

# Only air-gapped instances write to this table, so nothing populates it in development.
Gitlab::Seeder.quiet do
  next if Utilization::BillableUsage::DailyNamespaceAggregate.exists?

  root_namespace_id = Group.where(parent_id: nil).pick(:id)
  counter = Gitlab::BillingEvents::Client::COUNTER
  snapshot = Gitlab::BillingEvents::Client::SNAPSHOT

  events = [
    { event_type: 'secrets_read', unit_of_measure: 'request', quantity: 12, root_namespace_id: root_namespace_id,
      metadata: { feature_qualified_name: 'secrets_read' }, kind: counter },
    { event_type: 'secrets_stored', unit_of_measure: 'secret', quantity: 7, root_namespace_id: nil,
      metadata: { feature_qualified_name: 'secrets_stored' }, kind: snapshot },
    { event_type: 'agent_llm', unit_of_measure: 'token', quantity: 1500.5, root_namespace_id: root_namespace_id,
      metadata: { feature_qualified_name: 'software_development/v1', operation_type: 'regular' }, kind: counter }
  ]

  [Date.current, Date.current.prev_month].each do |usage_date|
    events.each do |event|
      context = event.except(:kind).merge(timestamp: usage_date.to_time(:utc).change(hour: 12))
      Utilization::BillableUsage::RecordAggregateService.new(context, quantity_kind: event[:kind]).execute

      print '.'
    end
  end
end
