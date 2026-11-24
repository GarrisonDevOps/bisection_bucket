# frozen_string_literal: true

module Resolvers
  module Groups
    class SavedReplyResolver < BaseResolver
      extension ::Gitlab::Graphql::Limit::FieldCallCount, limit: 1

      type ::Types::Groups::SavedReplyType, null: true

      alias_method :target, :object

      argument :id, Types::GlobalIDType[::Groups::SavedReply],
        required: true,
        description: 'Global ID of a saved reply.'

      def resolve(id:)
        ::Groups::SavedReply.find_saved_reply(group_id: object.id, id: id.model_id)
      end
    end
  end
end
