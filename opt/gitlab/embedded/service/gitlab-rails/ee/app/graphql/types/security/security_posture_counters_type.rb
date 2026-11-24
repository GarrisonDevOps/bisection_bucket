# frozen_string_literal: true

module Types
  module Security
    class SecurityPostureCountersType < BaseObject # rubocop:disable Graphql/AuthorizeTypes -- Authorization is done in resolver layer
      graphql_name 'SecurityPostureCounters'
      description 'Aggregated security posture counters for a namespace.'

      field :total, GraphQL::Types::Int,
        null: false,
        experiment: { milestone: '19.5' },
        description: 'Total number of unarchived projects in the namespace.'

      field :with_scanners, GraphQL::Types::Int,
        null: false,
        experiment: { milestone: '19.0' },
        description: 'Number of unarchived projects with at least one security scanner configured.'

      field :with_failures, GraphQL::Types::Int,
        null: false,
        experiment: { milestone: '19.0' },
        description: 'Number of unarchived projects with at least one failed scan.'

      field :with_stale, GraphQL::Types::Int,
        null: false,
        experiment: { milestone: '19.0' },
        description: 'Number of unarchived projects with at least one stale scan.'

      field :with_triage_coverage, GraphQL::Types::Int,
        null: true,
        experiment: { milestone: '19.5' },
        description: 'Count of unarchived projects in the group with at least one triage and remediation ' \
          'trigger enabled.'

      def with_triage_coverage
        return unless Ability.allowed?(current_user, :read_security_scan_profiles, context[:security_posture_group])

        object[:with_triage_coverage]
      end
    end
  end
end
