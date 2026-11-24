# frozen_string_literal: true

module Types
  module VirtualRegistries
    module Cleanup
      class PolicyType < ::Types::BaseObject
        graphql_name 'VirtualRegistryCleanupPolicy'
        description 'Represents a virtual registry cleanup policy'

        authorize :read_virtual_registry_cleanup_policy

        alias_method :policy, :object

        field :enabled, GraphQL::Types::Boolean, null: false,
          description: 'Whether the cleanup policy is enabled.',
          experiment: { milestone: '18.7' }

        field :keep_n_days_after_download, GraphQL::Types::Int, null: false,
          description: 'Number of days to keep cached entries after their last download.',
          experiment: { milestone: '18.7' }

        field :status, Types::VirtualRegistries::Cleanup::PolicyStatusEnum, null: false,
          description: 'Current execution status of the cleanup policy.',
          experiment: { milestone: '18.7' }

        field :cadence, GraphQL::Types::Int, null: false,
          description: 'Frequency in days for running the cleanup policy. Valid values: 1, 7, 14, 30, 90.',
          experiment: { milestone: '18.7' }

        field :failure_message, GraphQL::Types::String, null: true,
          description: 'Error message when the cleanup policy fails.',
          experiment: { milestone: '18.7' }

        field :next_run_at, ::Types::TimeType, null: true,
          description: 'Next time the virtual registry cleanup policy runs.',
          experiment: { milestone: '18.7' }

        field :created_at, Types::TimeType, null: false,
          description: 'Timestamp when the cleanup policy was created.',
          experiment: { milestone: '18.7' }

        field :updated_at, Types::TimeType, null: false,
          description: 'Timestamp when the cleanup policy was last updated.',
          experiment: { milestone: '18.7' }

        # rubocop:disable GraphQL/ExtractType -- Not worth extracting last_run_* and notify_on_* fields into a separate type
        # These attributes are stored directly on the VirtualRegistries::Cleanup::Policy model
        field :notify_on_success, GraphQL::Types::Boolean, null: false,
          description: 'Boolean to notify group owners on successful cleanup runs.',
          experiment: { milestone: '18.7' }

        field :notify_on_failure, GraphQL::Types::Boolean, null: false,
          description: 'Boolean to notify group owners on failed cleanup runs.',
          experiment: { milestone: '18.7' }

        field :last_run_at, ::Types::TimeType, null: true,
          description: 'Last time that the virtual registry cleanup policy executed.',
          experiment: { milestone: '18.7' }

        field :last_run_deleted_size, GraphQL::Types::BigInt, null: true,
          description: 'Size in bytes of data deleted during the last cleanup run.',
          experiment: { milestone: '18.7' }

        field :last_run_deleted_entries_count, GraphQL::Types::Int, null: true,
          description: 'Number of entries deleted during the last cleanup run.',
          experiment: { milestone: '18.7' }

        field :last_run_detailed_metrics, ::Types::VirtualRegistries::Cleanup::PolicyLastRunDetailedMetricsType,
          null: true,
          description: 'Detailed metrics from the last cleanup run.',
          experiment: { milestone: '18.7' }
        # rubocop:enable GraphQL/ExtractType
      end
    end
  end
end
