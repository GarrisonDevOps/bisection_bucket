# frozen_string_literal: true

module Resolvers
  module Ai
    module Governance
      class GroupSessionsResolver < BaseSessionsResolver
        type ::Types::Ai::Governance::SessionType.connection_type, null: true

        argument :project_path, GraphQL::Types::String,
          required: false,
          description: 'Filter by project full path.'

        private

        def resolver_namespace
          object
        end

        def finder_params(args)
          super.merge(project_path: args[:project_path]).compact
        end
      end
    end
  end
end
