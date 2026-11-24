# frozen_string_literal: true

module Mutations
  module Security
    module ProjectTrackedContexts
      class Destroy < BaseMutation
        graphql_name 'SecurityRefsUntrack'

        argument :ref_ids, [::Types::GlobalIDType[::Security::ProjectTrackedContext]],
          required: true,
          description: 'Global IDs of the tracked refs to stop tracking.'

        field :untracked_ref_ids, [GraphQL::Types::ID],
          null: true,
          description: 'Global IDs of refs that were successfully untracked.'

        authorize :delete_security_project_tracked_ref

        def resolve(ref_ids:)
          ref_ids.each_with_object({ untracked_ref_ids: [], errors: [] }) do |ref_gid, response|
            tracked_context = authorized_find!(id: ref_gid)

            result = ::Security::ProjectTrackedContexts::DestroyService.new(
              tracked_context: tracked_context,
              current_user: current_user
            ).execute

            if result.success?
              response[:untracked_ref_ids] << ref_gid
            else
              response[:errors] << result.message
            end
          end
        end
      end
    end
  end
end
