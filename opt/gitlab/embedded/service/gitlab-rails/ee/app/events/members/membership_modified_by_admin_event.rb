# frozen_string_literal: true

module Members
  class MembershipModifiedByAdminEvent < ::Gitlab::EventStore::Event
    def schema
      {
        'type' => 'object',
        'required' => %w[member_user_id],
        'properties' => {
          'member_user_id' => { 'type' => 'integer' }
        }
      }
    end
  end
end
