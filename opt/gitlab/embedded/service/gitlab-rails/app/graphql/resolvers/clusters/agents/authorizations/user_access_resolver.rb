# frozen_string_literal: true

module Resolvers
  module Clusters
    module Agents
      module Authorizations
        class UserAccessResolver < BaseResolver
          type Types::Clusters::Agents::Authorizations::UserAccessType, null: true

          authorize_granular_token permissions: :read_cluster_agent, boundary: :itself, boundary_type: :project

          alias_method :project, :object

          def resolve(*)
            ::Clusters::Agents::Authorizations::UserAccess::Finder.new(current_user, project: project).execute
          end
        end
      end
    end
  end
end
