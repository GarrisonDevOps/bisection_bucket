# frozen_string_literal: true

module Mutations
  module Groups
    module SavedReplies
      class Update < ::Mutations::SavedReplies::Update
        graphql_name 'GroupSavedReplyUpdate'

        authorize_granular_token permissions: :update_saved_reply,
          boundary_argument: :id,
          boundary: :group,
          boundary_type: :group

        field :saved_reply, ::Types::Groups::SavedReplyType,
          null: true,
          description: 'Saved reply after mutation.'

        argument :id, Types::GlobalIDType[::Groups::SavedReply],
          required: true,
          description: copy_field_description(::Types::Groups::SavedReplyType, :id)
      end
    end
  end
end
