# frozen_string_literal: true

module Types
  module Security
    module ScanProfiles
      # rubocop:disable Graphql/AuthorizeTypes -- Authorization occurs at parent level (ScanProfileType)
      class AutoRemediationConfigurationType < BaseObject
        graphql_name 'AutoRemediationConfiguration'
        description 'Auto-remediation configuration for a dependency scanning post-processing scan profile.'

        authorize_granular_token skip_reason: :parent_authorizes

        field :enabled, GraphQL::Types::Boolean,
          null: true,
          description: 'Indicates whether auto-remediation is enabled.'

        field :cooldown, GraphQL::Types::Int,
          null: true,
          description: 'Minimum number of days after a package is released before it can be used.'

        field :severity_level, ::Types::VulnerabilitySeverityEnum,
          null: true,
          description: 'Minimum vulnerability severity that triggers an automated upgrade.'

        field :upgrade_policy, ::Types::Security::ScanProfiles::UpgradePolicyEnum,
          null: true,
          description: 'Highest version bump allowed when remediating.'

        field :open_merge_requests_limit, GraphQL::Types::Int,
          null: true,
          description: 'Maximum number of open merge requests the feature may have open at once.'

        field :runner_tags, [GraphQL::Types::String],
          null: true,
          description: 'Runner tags used for auto-remediation jobs.'

        field :batch_updates, GraphQL::Types::Boolean,
          null: true,
          description: 'Indicates whether updates are batched into one merge request per lockfile.'

        field :max_updates_per_batch, GraphQL::Types::Int,
          null: true,
          description: 'Maximum number of dependency updates in one batch merge request. ' \
            'Further updates wait for the next run.'
      end
      # rubocop:enable Graphql/AuthorizeTypes
    end
  end
end
