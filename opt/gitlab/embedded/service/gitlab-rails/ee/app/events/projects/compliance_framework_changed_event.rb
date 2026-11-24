# frozen_string_literal: true

module Projects
  class ComplianceFrameworkChangedEvent < ::Gitlab::EventStore::Event
    EVENT_TYPES = {
      added: 'added',
      removed: 'removed'
    }.freeze

    def schema
      {
        'type' => 'object',
        'properties' => {
          'project_id' => { 'type' => 'integer' },
          'compliance_framework_id' => { 'type' => 'integer' },
          'event_type' => { 'type' => 'string', 'enum' => EVENT_TYPES.values }
        },
        'required' => %w[project_id compliance_framework_id event_type]
      }
    end
  end
end
