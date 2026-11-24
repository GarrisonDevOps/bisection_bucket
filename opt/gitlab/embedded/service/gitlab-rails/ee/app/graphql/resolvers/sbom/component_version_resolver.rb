# frozen_string_literal: true

module Resolvers
  module Sbom
    class ComponentVersionResolver < BaseResolver
      include Gitlab::Graphql::Authorize::AuthorizeResource

      type [::Types::Sbom::ComponentVersionType], null: true

      description 'Software dependency versions, filtered by component'

      argument :component_name, ::GraphQL::Types::String,
        required: true,
        description: 'Name of the SBoM component.'

      def resolve(component_name: nil)
        ::Sbom::ComponentVersionsFinder.new(object, component_name).execute
      end
    end
  end
end
