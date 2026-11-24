# frozen_string_literal: true

module Types
  module Security
    class TriageAndRemediationCoverageCountersType < BaseObject # rubocop:disable Graphql/AuthorizeTypes -- Authorization is done in the resolver
      graphql_name 'TriageAndRemediationCoverageCounters'
      description 'Triage and remediation coverage counters for a namespace.'

      authorize_granular_token permissions: :read_security_scan_profiles,
        boundary: :group, boundary_type: :group

      Adapter = Struct.new(:enabled_count, :auto_count, :flow_missing_count, :group, keyword_init: true)

      field :enabled_count, GraphQL::Types::Int,
        null: false,
        experiment: { milestone: '19.5' },
        description: 'Count of unarchived projects in the group where the trigger type is attached.'

      field :auto_count, GraphQL::Types::Int,
        null: false,
        experiment: { milestone: '19.5' },
        description: 'Count of unarchived projects in the group where the trigger type is attached and ' \
          'set to automatic.'

      field :flow_missing_count, GraphQL::Types::Int,
        null: false,
        experiment: { milestone: '19.6' },
        description: 'Count of unarchived projects in the group where the trigger type is attached but ' \
          'the AI flow behind it is missing.'
    end
  end
end
