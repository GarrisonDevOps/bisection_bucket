# frozen_string_literal: true

module Types
  module Projects
    class SavedReplyType < ::Types::SavedReplyType
      graphql_name 'ProjectSavedReply'

      authorize :read_saved_reply
      authorize_granular_token permissions: :read_saved_reply, boundary: :project, boundary_type: :project

      field :id, Types::GlobalIDType[::Projects::SavedReply],
        null: false,
        description: 'Global ID of the project-level saved reply.'
    end
  end
end
