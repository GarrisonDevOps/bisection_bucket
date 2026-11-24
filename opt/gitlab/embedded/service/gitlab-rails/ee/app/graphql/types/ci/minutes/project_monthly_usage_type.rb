# frozen_string_literal: true

module Types
  module Ci
    module Minutes
      # rubocop: disable Graphql/AuthorizeTypes
      # this type only exposes data related to the current user
      class ProjectMonthlyUsageType < BaseObject
        graphql_name 'CiMinutesProjectMonthlyUsage'

        field :minutes,
          ::GraphQL::Types::Int,
          null: true,
          method: :amount_used,
          description: 'Number of compute minutes used by the project in the month.'

        field :shared_runners_duration,
          ::GraphQL::Types::Int,
          null: true,
          description: 'Total duration (in seconds) of shared runners use by the project for the month.'

        field :project,
          Types::ProjectType,
          null: true,
          description: 'Project having the recorded usage.'

        def name
          object.project&.name
        end

        def project
          BatchLoader::GraphQL.for(object.project_id).batch(key: current_user) do |project_ids, loader, args|
            projects_with_details(project_ids, args[:key]).each { |project| loader.call(project.id, project) }
          end
        end

        private

        def projects_with_details(project_ids, user)
          projects = ::Project.id_in(project_ids).inc_routes.to_a
          ::Preloaders::ProjectPolicyPreloader.new(projects, user).execute
          projects
        end
      end
    end
  end
end
