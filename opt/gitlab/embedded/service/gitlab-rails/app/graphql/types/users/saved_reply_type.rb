# frozen_string_literal: true

module Types
  module Users
    class SavedReplyType < ::Types::SavedReplyType
      graphql_name 'SavedReply'

      authorize :read_saved_reply
      authorize_granular_token permissions: :read_saved_reply, boundary: :user, boundary_type: :user

      field :id, Types::GlobalIDType[::Users::SavedReply],
        null: false,
        description: 'Global ID of the user saved reply.'
    end
  end
end
