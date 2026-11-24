# frozen_string_literal: true

module Govern
  module PolicyEngine
    module Impact
      # The policy an impact run analyses before it is saved. The resolver is
      # written for a policy, so the draft is one: an unsaved, read-only row
      # carrying what the editor has authored so far. Whatever the resolver
      # reads off a stored policy it can read here, and a save raises.
      module Draft
        def self.build(organization_id:, namespace_id:, policy_scope:, rules:)
          ::Govern::Policy.new(
            organization_id: organization_id, namespace_id: namespace_id, policy_scope: policy_scope, rules: rules
          ).tap(&:readonly!)
        end
      end
    end
  end
end
