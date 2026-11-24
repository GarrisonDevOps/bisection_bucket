# frozen_string_literal: true

module Resolvers
  module Security
    class DependencyFirewallActivitySummaryResolver < BaseResolver
      authorize_granular_token permissions: :read_security_policy,
        boundaries: [
          { boundary: :itself, boundary_type: :project },
          { boundary: :itself, boundary_type: :group }
        ]

      type ::Types::Security::DependencyFirewallActivitySummaryType, null: true

      argument :from, ::Types::DateType, required: false,
        description: 'Start date (inclusive) of the activity window. Defaults to 7 days ago.'
      argument :to, ::Types::DateType, required: false,
        description: 'End date (inclusive) of the activity window. Defaults to the current date.'

      def resolve(from: nil, to: nil)
        ::Security::DependencyFirewallRuleActivityFinder
          .new(object, current_user, from: from, to: to)
          .activity_summary
      end
    end
  end
end
