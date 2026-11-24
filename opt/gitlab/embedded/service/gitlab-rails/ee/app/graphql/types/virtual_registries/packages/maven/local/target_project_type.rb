# frozen_string_literal: true

module Types
  module VirtualRegistries
    module Packages
      module Maven
        module Local
          class TargetProjectType < ::Types::BaseObject
            graphql_name 'MavenLocalUpstreamTargetProject'
            description 'Project a Maven local upstream registry serves packages from.'

            authorize :read_project

            authorize_granular_token skip_reason: :parent_authorizes

            field :id, GraphQL::Types::ID, null: false,
              description: 'ID of the project.',
              experiment: { milestone: '19.5' }

            field :full_path, GraphQL::Types::ID, null: false,
              description: 'Full path of the project.',
              experiment: { milestone: '19.5' }

            field :web_url, GraphQL::Types::String, null: true,
              description: 'Web URL of the project.',
              experiment: { milestone: '19.5' }
          end
        end
      end
    end
  end
end
