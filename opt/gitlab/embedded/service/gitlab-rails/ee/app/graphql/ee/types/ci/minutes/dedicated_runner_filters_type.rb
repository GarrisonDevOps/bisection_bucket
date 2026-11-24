# frozen_string_literal: true

# rubocop:disable Gitlab/EeOnlyClass -- This is only used in GitLab dedicated that comes under ultimate tier only.
module EE
  module Types
    module Ci
      module Minutes
        class DeletedRunnerType < ::Types::BaseObject
          graphql_name 'CiDeletedRunner'
          description 'Reference to a deleted runner'

          authorize_granular_token parent_authorizes: :read_dedicated_hosted_runner_usage

          field :id, ::Types::GlobalIDType[::Ci::Runner], null: false,
            description: 'Global ID of the deleted runner.'
        end

        class DedicatedRunnerFiltersType < ::Types::BaseObject
          graphql_name 'CiDedicatedHostedRunnerFilters'
          description 'Filter options available for GitLab Dedicated runner usage data.'

          include ::Gitlab::Graphql::Authorize::AuthorizeResource
          include ::Gitlab::Utils::StrongMemoize

          authorize :read_dedicated_hosted_runner_usage
          authorize_granular_token permissions: :read_dedicated_hosted_runner_usage, boundary: :instance,
            boundary_type: :instance, assignable_when: [:admin]

          DeletedRunner = Struct.new(:db_id) do
            def to_global_id
              ::Gitlab::GlobalId.build(model_name: ::Ci::Runner.name, id: db_id)
            end
          end

          field :deleted_runners, DeletedRunnerType.connection_type, null: true,
            description: 'List of runner IDs from usage data without associated runner records.'
          field :runners, ::Types::Ci::RunnerType.connection_type, null: true,
            description: 'List of unique runners with usage data.'
          field :years, [GraphQL::Types::Int], null: true,
            description: 'List of years with available usage data.'

          def runners
            found_runners
          end

          def deleted_runners
            deleted_ids = all_runner_ids - found_runners.map(&:id)

            deleted_ids.map { |db_id| DeletedRunner.new(db_id) }
          end

          def years
            ::Ci::Minutes::GitlabHostedRunnerMonthlyUsage.distinct_years
          end

          private

          def found_runners
            ::Ci::RunnersFinder
              .new(current_user: context[:current_user], params: { id_in: all_runner_ids })
              .execute
          end
          strong_memoize_attr :found_runners

          def all_runner_ids
            ::Ci::Minutes::GitlabHostedRunnerMonthlyUsage.distinct_runner_ids
          end
          strong_memoize_attr :all_runner_ids
        end
      end
    end
  end
end
# rubocop:enable Gitlab/EeOnlyClass
