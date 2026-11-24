# frozen_string_literal: true

module Mutations
  module Groups
    module SavedReplies
      class Create < ::Mutations::SavedReplies::Create
        graphql_name 'GroupSavedReplyCreate'

        authorize_granular_token permissions: :create_saved_reply,
          boundary_argument: :group_id,
          boundary_type: :group

        field :saved_reply, ::Types::Groups::SavedReplyType,
          null: true,
          description: 'Saved reply after mutation.'

        argument :group_id, ::Types::GlobalIDType[::Group],
          required: true,
          description: 'Group for the save reply.'

        def resolve(group_id:, name:, content:)
          group = authorized_find!(id: group_id)

          result = ::SavedReplies::CreateService.new(object: group, name: name, content: content).execute
          present_result(result)
        end
      end
    end
  end
end
