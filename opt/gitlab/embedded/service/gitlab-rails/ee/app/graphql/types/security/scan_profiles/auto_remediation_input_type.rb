# frozen_string_literal: true

module Types
  module Security
    module ScanProfiles
      class AutoRemediationInputType < BaseInputObject
        graphql_name 'SecurityScanProfileAutoRemediationInput'
        description 'Auto-remediation configuration for a dependency scanning post-processing scan profile.'

        argument :enabled, GraphQL::Types::Boolean,
          required: false,
          experiment: { milestone: '19.3' },
          description: 'Whether auto-remediation is enabled.'

        argument :cooldown, GraphQL::Types::Int,
          required: false,
          experiment: { milestone: '19.3' },
          description: 'Minimum number of days after a package is released before it can be used.'

        argument :severity_level, ::Types::VulnerabilitySeverityEnum,
          required: false,
          experiment: { milestone: '19.3' },
          description: 'Minimum vulnerability severity that triggers an automated upgrade. ' \
            'Findings below this threshold are skipped.'

        argument :upgrade_policy, ::Types::Security::ScanProfiles::UpgradePolicyEnum,
          required: false,
          experiment: { milestone: '19.3' },
          description: 'Highest version bump allowed when remediating.'

        argument :open_merge_requests_limit, GraphQL::Types::Int,
          required: false,
          experiment: { milestone: '19.3' },
          description: 'Maximum number of open auto-remediation merge requests at once.'

        argument :runner_tags, [GraphQL::Types::String],
          required: false,
          experiment: { milestone: '19.6' },
          description: 'Runner tags applied to the auto-remediation job.'

        argument :batch_updates, GraphQL::Types::Boolean,
          required: false,
          experiment: { milestone: '19.7' },
          description: 'Whether to batch updates into one merge request per lockfile.'

        argument :max_updates_per_batch, GraphQL::Types::Int,
          required: false,
          experiment: { milestone: '19.7' },
          description: 'Maximum number of dependency updates in one batch merge request. ' \
            'Further updates wait for the next run.'
      end
    end
  end
end
