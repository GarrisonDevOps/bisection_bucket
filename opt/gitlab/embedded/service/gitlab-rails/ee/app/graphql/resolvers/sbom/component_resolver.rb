# frozen_string_literal: true

module Resolvers
  module Sbom
    class ComponentResolver < BaseResolver
      include Gitlab::Graphql::Authorize::AuthorizeResource

      type [::Types::Sbom::ComponentType], null: true

      description 'Software dependencies, optionally filtered by name'

      argument :name, ::GraphQL::Types::String, required: false,
        description: 'Entire name or part of the name.'

      alias_method :namespace, :object

      def resolve(name: nil)
        ::Sbom::ComponentsFinder.new(namespace, name).execute
      end
    end
  end
end
