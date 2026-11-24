# frozen_string_literal: true

module Types
  module Analytics
    module AiUsage
      # rubocop:disable Graphql/AuthorizeTypes -- authorized in parent type.
      class AiInstanceUsageEventType < AiUsageEventType
        graphql_name 'AiInstanceUsageEvent'

        field :namespace_path, GraphQL::Types::String, null: true,
          description: 'Namespace hierarchy for Namespace or ProjectNamespace associated with the event.'

        field :extras, GraphQL::Types::JSON, null: true, description: 'Associated event context data.' # rubocop:disable Graphql/JSONType -- its an open structure

        def namespace_path
          return object['namespace_path'] if object['namespace_path']

          BatchLoader::GraphQL.for(object.namespace_id).batch(key: :namespace_traversal_path) do |ids, loader|
            namespaces = ::Namespace.id_in(ids).index_by(&:id)
            ids.each { |id| loader.call(id, namespaces[id]&.traversal_path(with_organization: false)) }
          end
        end
      end
      # rubocop:enable Graphql/AuthorizeTypes
    end
  end
end
