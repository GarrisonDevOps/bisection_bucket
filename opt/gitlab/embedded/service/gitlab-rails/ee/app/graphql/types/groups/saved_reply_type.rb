# frozen_string_literal: true

module Types
  module Groups
    class SavedReplyType < ::Types::SavedReplyType
      graphql_name 'GroupSavedReply'

      authorize :read_saved_reply
      authorize_granular_token permissions: :read_saved_reply, boundary: :group, boundary_type: :group

      field :id, Types::GlobalIDType[::Groups::SavedReply],
        null: false,
        description: 'Global ID of the group-level saved reply.'
    end
  end
end
