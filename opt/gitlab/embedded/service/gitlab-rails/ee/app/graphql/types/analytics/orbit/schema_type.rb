# frozen_string_literal: true

module Types
  module Analytics
    module Orbit
      class SchemaType < BaseObject # rubocop:disable Graphql/AuthorizeTypes -- parent field authorizes
        graphql_name 'OrbitSchema'
        description 'Node kinds and edge kinds that the current user can query in Orbit.'

        authorize_granular_token skip_reason: :parent_authorizes

        def self.authorization_scopes
          super + [:ai_workflows]
        end

        field :edges, SchemaEdgeType.connection_type, null: false,
          scopes: AI_WORKFLOW_SCOPES,
          description: 'Edge kinds.'
        field :nodes, SchemaNodeType.connection_type, null: false,
          scopes: AI_WORKFLOW_SCOPES,
          description: 'Node kinds.'

        def edges
          nodes_by_name = object[:nodes].index_by { |node| node[:name] }

          object[:edges].map do |edge|
            endpoints = edge[:variants].filter_map do |variant|
              source = nodes_by_name[variant[:source_type]]
              target = nodes_by_name[variant[:target_type]]
              { source: source, target: target } if source && target
            end

            edge.merge(endpoints: endpoints)
          end
        end
      end
    end
  end
end
