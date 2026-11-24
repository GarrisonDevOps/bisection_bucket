# frozen_string_literal: true

module Projects
  class SecurityAttributeChangedEvent < ::Gitlab::EventStore::Event
    EVENT_TYPES = {
      added: 'added',
      removed: 'removed'
    }.freeze

    def schema
      {
        'type' => 'object',
        'properties' => {
          'project_id' => { 'type' => 'integer' },
          'security_attribute_id' => { 'type' => 'integer' },
          'event_type' => { 'type' => 'string', 'enum' => EVENT_TYPES.values }
        },
        'required' => %w[project_id security_attribute_id event_type]
      }
    end
  end
end
