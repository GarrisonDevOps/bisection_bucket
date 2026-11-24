# frozen_string_literal: true

module Types
  module Ai
    module Governance
      # Reachable only through fields that already authorize against the
      # group or project, so no object-level authorization is needed here.
      class ProjectActivityType < BaseObject # rubocop:disable Graphql/AuthorizeTypes -- parent field authorizes
        graphql_name 'AiGovernanceProjectActivity'
        description 'AI session activity in a single project.'

        authorize_granular_token skip_reason: :parent_authorizes

        field :project, Types::ProjectType, null: true,
          description: 'Project the sessions ran in. Resolves to null when the current ' \
            'user cannot read the project.'
        field :session_count, GraphQL::Types::Int, null: true,
          description: 'Number of AI sessions in the project in the selected timeframe.'

        def project
          Gitlab::Graphql::Loaders::BatchModelLoader.new(Project, object[:project_id], [:route]).find
        end
      end
    end
  end
end
