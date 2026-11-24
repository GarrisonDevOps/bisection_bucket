# frozen_string_literal: true

module API
  module Entities
    class SecurityPolicyConfiguration < Grape::Entity
      expose :cadence, documentation: { type: 'String' }
      expose :namespaces, documentation: { type: 'String', is_array: true }
      expose :updated_at, documentation: { type: 'String' } do |policy|
        policy[:config].policy_last_updated_at.to_datetime.to_s
      end
    end
  end
end
