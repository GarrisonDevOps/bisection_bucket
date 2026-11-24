# frozen_string_literal: true

module Security
  class PolicyDeletedEvent < ::Gitlab::EventStore::Event
    def schema
      {
        'type' => 'object',
        'properties' => {
          'security_policy_id' => { 'type' => 'integer' }
        },
        'required' => %w[security_policy_id]
      }
    end
  end
end
