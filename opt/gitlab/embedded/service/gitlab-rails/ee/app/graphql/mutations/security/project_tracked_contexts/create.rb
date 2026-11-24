# frozen_string_literal: true

module Mutations
  module Security
    module ProjectTrackedContexts
      class Create < BaseMutation
        graphql_name 'SecurityRefsTrack'

        argument :project_path, GraphQL::Types::ID,
          required: true,
          description: 'Full path of the project.'

        argument :refs, [Types::Security::TrackedRefInputType],
          required: true,
          description: 'Array of refs to be tracked.'

        field :tracked_refs, [Types::Security::TrackedRefType],
          null: true,
          description: 'Refs that were successfully tracked.'

        field :errors, [GraphQL::Types::String],
          null: false,
          description: 'Errors encountered during the operation.'

        authorize :create_security_project_tracked_ref

        authorize_granular_token permissions: :create_security_project_tracked_ref,
          boundary_argument: :project_path, boundary_type: :project

        def resolve(project_path:, refs:)
          project = find_project_by_path(project_path)
          return { tracked_refs: [], errors: ['Project not found'] } unless project

          return { tracked_refs: [], errors: ['Feature not available'] } unless ::Security::VAC.enabled?(project)

          unless Ability.allowed?(current_user, :create_security_project_tracked_ref, project)
            return { tracked_refs: [], errors: ['Insufficient permissions'] }
          end

          refs.each_with_object({ tracked_refs: [], errors: [] }) do |ref_input, response|
            result = ::Security::ProjectTrackedContexts::CreateService.new(
              project: project,
              context_name: ref_input.name,
              context_type: ref_input.ref_type,
              is_default: false
            ).execute

            if result.success?
              response[:tracked_refs] << result.payload[:tracked_context]
            else
              response[:errors] << result.message
            end
          end
        end

        private

        def find_project_by_path(project_path)
          Project.find_by_full_path(project_path)
        end
      end
    end
  end
end
