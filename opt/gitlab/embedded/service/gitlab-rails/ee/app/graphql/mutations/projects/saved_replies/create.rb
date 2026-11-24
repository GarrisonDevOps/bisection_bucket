# frozen_string_literal: true

module Mutations
  module Projects
    module SavedReplies
      class Create < ::Mutations::SavedReplies::Create
        graphql_name 'ProjectSavedReplyCreate'

        authorize_granular_token permissions: :create_saved_reply,
          boundary_argument: :project_id,
          boundary_type: :project

        field :saved_reply, ::Types::Projects::SavedReplyType,
          null: true,
          description: 'Saved reply after mutation.'

        argument :project_id, ::Types::GlobalIDType[::Project],
          required: true,
          description: 'Project for the saved reply.'

        def resolve(project_id:, name:, content:)
          project = authorized_find!(id: project_id)

          result = ::SavedReplies::CreateService.new(object: project, name: name, content: content).execute
          present_result(result)
        end
      end
    end
  end
end
