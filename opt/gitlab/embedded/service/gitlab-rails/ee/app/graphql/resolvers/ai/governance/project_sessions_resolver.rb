# frozen_string_literal: true

module Resolvers
  module Ai
    module Governance
      class ProjectSessionsResolver < BaseSessionsResolver
        type ::Types::Ai::Governance::SessionType.connection_type, null: true

        private

        # Project-scoped sessions live in the project's namespace.
        def resolver_namespace
          object.project_namespace
        end
      end
    end
  end
end
