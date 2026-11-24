# frozen_string_literal: true

module Resolvers
  module Security
    class DependencyFirewallRuleActivityResolver < BaseResolver
      authorize_granular_token permissions: :read_security_policy,
        boundaries: [
          { boundary: :itself, boundary_type: :project },
          { boundary: :itself, boundary_type: :group }
        ]

      type [::Types::Security::DependencyFirewallRuleActivityType], null: true

      argument :from, ::Types::DateType, required: false,
        description: 'Start date (inclusive) of the activity window. Defaults to 7 days ago.'
      argument :to, ::Types::DateType, required: false,
        description: 'End date (inclusive) of the activity window. Defaults to the current date.'

      def resolve(from: nil, to: nil)
        ::Security::DependencyFirewallRuleActivityFinder
          .new(object, current_user, from: from, to: to)
          .execute
      end
    end
  end
end
