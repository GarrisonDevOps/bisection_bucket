# frozen_string_literal: true

module Types
  module VirtualRegistries
    module Packages
      module Maven
        module Local
          class TargetGroupType < ::Types::BaseObject
            graphql_name 'MavenLocalUpstreamTargetGroup'
            description 'Group a Maven local upstream registry serves packages from.'

            authorize :read_group

            authorize_granular_token skip_reason: :parent_authorizes

            field :id, GraphQL::Types::ID, null: false,
              description: 'ID of the group.',
              experiment: { milestone: '19.5' }

            field :full_path, GraphQL::Types::ID, null: false,
              description: 'Full path of the group.',
              experiment: { milestone: '19.5' }

            field :web_url, GraphQL::Types::String, null: true,
              description: 'Web URL of the group.',
              experiment: { milestone: '19.5' }
          end
        end
      end
    end
  end
end
