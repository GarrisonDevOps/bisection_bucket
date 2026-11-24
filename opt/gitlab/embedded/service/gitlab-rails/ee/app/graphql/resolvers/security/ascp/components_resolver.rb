# frozen_string_literal: true

module Resolvers
  module Security
    module Ascp
      class ComponentsResolver < BaseResolver
        include Gitlab::Graphql::Authorize::AuthorizeResource
        include LooksAhead

        type Types::Security::Ascp::ComponentType.connection_type, null: true

        authorize :read_ascp_component
        authorizes_object!

        description 'Find logical components of a project identified by ASCP security scanning.'

        argument :title, GraphQL::Types::String,
          required: false,
          description: 'Filter by component title (case-insensitive partial match).'

        argument :sub_directory, GraphQL::Types::String,
          required: false,
          description: 'Filter by exact sub-directory path.'

        def resolve_with_lookahead(**args)
          apply_lookahead(
            ::Security::Ascp::ComponentsFinder.new(
              project: object,
              params: args
            ).execute
          )
        end

        private

        def preloads
          {
            scan: [:scan],
            security_context: [{ security_context: [:scan, :guidelines] }],
            dependencies: [{ dependencies: :dependency }]
          }
        end
      end
    end
  end
end
