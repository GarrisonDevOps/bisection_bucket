# frozen_string_literal: true

module Security
  class PolicyCreatedEvent < ::Gitlab::EventStore::Event
    def schema
      {
        'type' => 'object',
        'properties' => {
          'security_policy_id' => { 'type' => 'integer' },
          'triggered_by_assign' => { 'type' => 'boolean' }
        },
        'required' => %w[security_policy_id]
      }
    end
  end
end
