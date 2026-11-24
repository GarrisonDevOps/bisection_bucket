# frozen_string_literal: true

module Types
  module Ci
    # rubocop: disable Graphql/AuthorizeTypes -- the read_runner_usage permission is already checked by the resolver
    class RunnerUsageByProjectType < BaseObject
      graphql_name 'CiRunnerUsageByProject'
      description 'Runner usage in minutes by project.'

      field :project, ::Types::ProjectType,
        null: true, description: 'Project that the usage refers to. Null means "Other projects".'

      field :ci_duration, GraphQL::Types::BigInt,
        null: false,
        description: 'Number of minutes spent to process jobs during the selected period. Encoded as a string.',
        hash_key: :ci_minutes_used

      # TODO: Remove in 18.0. For more details read https://gitlab.com/gitlab-org/gitlab/-/issues/497364
      field :ci_minutes_used, GraphQL::Types::BigInt,
        null: false, description: 'Amount of minutes used during the selected period. Encoded as a string.',
        deprecated: { reason: 'Use `ciDuration`', milestone: '17.5' }

      field :ci_build_count, GraphQL::Types::BigInt,
        null: false, description: 'Amount of builds executed during the selected period. Encoded as a string.'

      def project
        return unless object[:project_id]

        BatchLoader::GraphQL.for(object[:project_id]).batch do |project_ids, loader|
          Project.id_in(project_ids).each do |project|
            loader.call(project.id, project)
          end
        end
      end
    end
    # rubocop: enable Graphql/AuthorizeTypes
  end
end
