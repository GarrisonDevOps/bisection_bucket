# frozen_string_literal: true

# rubocop:disable Gitlab/EeOnlyClass -- This is only used in GitLab dedicated that comes under ultimate tier only.
module EE
  module Resolvers
    module Ci
      module Minutes
        class DedicatedMonthlyUsageResolver < ::Resolvers::BaseResolver
          include ::Gitlab::Graphql::Authorize::AuthorizeResource
          include LooksAhead

          type ::EE::Types::Ci::Minutes::DedicatedMonthlyUsageType.connection_type, null: true

          argument :billing_month, GraphQL::Types::ISO8601Date, required: false,
            description: 'First day of the month to retrieve data for.'

          argument :year, GraphQL::Types::Int, required: false,
            description: 'Year to retrieve data for.'

          argument :grouping, EE::Types::Ci::Minutes::GroupingEnum, required: true,
            description: 'Groups usage data by instance aggregate or root namespace.'

          argument :runner_id, ::Types::GlobalIDType[::Ci::Runner], required: false,
            description: 'Filter usage data for a specific runner.'

          def resolve(**args)
            grouping = args[:grouping]
            billing_month = args[:billing_month]
            year = args[:year]
            runner_id = args[:runner_id]&.model_id

            case grouping
            when 'INSTANCE_AGGREGATE'
              resolve_instance_aggregate(billing_month, year, runner_id)
            when 'PER_ROOT_NAMESPACE'
              resolve_per_root_namespace(billing_month, year, runner_id)
            end
          end

          private

          def resolve_instance_aggregate(billing_month, year, runner_id)
            ::Ci::Minutes::GitlabHostedRunnerMonthlyUsage
              .instance_aggregate(billing_month, year, runner_id).to_a
          end

          def resolve_per_root_namespace(billing_month, year, runner_id)
            ::Ci::Minutes::GitlabHostedRunnerMonthlyUsage
              .per_root_namespace(billing_month, year, runner_id).to_a
          end
        end
      end
    end
  end
end
# rubocop:enable Gitlab/EeOnlyClass
