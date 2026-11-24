# frozen_string_literal: true

module Security
  class PolicyDismissalPreservedEvent < ::Gitlab::EventStore::Event
    def schema
      {
        'type' => 'object',
        'properties' => {
          'security_policy_dismissal_id' => { 'type' => 'integer' }
        },
        'required' => %w[security_policy_dismissal_id]
      }
    end
  end
end
