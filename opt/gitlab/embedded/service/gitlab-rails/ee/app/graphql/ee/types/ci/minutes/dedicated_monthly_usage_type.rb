# frozen_string_literal: true

# rubocop:disable Gitlab/EeOnlyClass -- TODO: move to ee/app/graphql/types/ci/minutes/dedicated_monthly_usage_type.rb
module EE
  module Types
    module Ci
      module Minutes
        class DedicatedMonthlyUsageType < ::Types::BaseObject
          graphql_name 'CiDedicatedHostedRunnerUsage'
          description 'Compute usage data for hosted runners on GitLab Dedicated.'

          authorize :read_dedicated_hosted_runner_usage
          authorize_granular_token permissions: :read_dedicated_hosted_runner_usage, boundary: :instance,
            boundary_type: :instance, assignable_when: [:admin]

          field :billing_month, GraphQL::Types::String, null: false,
            method: :billing_month_formatted,
            description: 'Month of the usage data.'

          field :root_namespace, ::Types::Ci::Minutes::NamespaceUnionType, null: true,
            description: 'Namespace associated with the usage data. Null for instance aggregate data.'

          field :billing_month_iso8601, GraphQL::Types::ISO8601Date, null: false, # rubocop:disable GraphQL/ExtractType -- we need it separate
            description: 'Timestamp of the billing month in ISO 8601 format.'

          field :compute_minutes, GraphQL::Types::Int, null: false,
            description: 'Total compute minutes used across all namespaces. ' \
              'Values are rounded down to the nearest integer.'

          field :duration_seconds, GraphQL::Types::Int, null: false,
            description: 'Total duration in seconds of runner usage. Values are rounded down to the nearest integer.'
          # rubocop:disable GraphQL/ExtractType -- we should deprecate the rounded fields
          field :compute_minutes_usage, GraphQL::Types::Float, null: false,
            description: 'Total compute minutes used across all namespaces.'

          field :duration_minutes, GraphQL::Types::Float, null: false,
            description: 'Total duration in minutes of runner usage.'
          # rubocop:enable GraphQL/ExtractType

          def compute_minutes_usage
            # Return the precise float value from the aggregated query
            object.compute_minutes.to_f
          end

          def duration_minutes
            # Convert duration_seconds to minutes as float
            object.duration_seconds.to_f / 60.0
          end

          def root_namespace
            return unless object.root_namespace_id.present?

            existing_namespace = object.root_namespace
            return existing_namespace if existing_namespace.present?

            ::Types::Ci::Minutes::DeletedNamespaceType::DeletedNamespace.new(
              object.root_namespace_id
            )
          end
        end
      end
    end
  end
end
# rubocop:enable Gitlab/EeOnlyClass
