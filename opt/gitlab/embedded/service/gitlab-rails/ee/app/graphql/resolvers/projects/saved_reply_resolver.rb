# frozen_string_literal: true

module Resolvers
  module Projects
    class SavedReplyResolver < BaseResolver
      type ::Types::Projects::SavedReplyType, null: true

      alias_method :target, :object

      argument :id, Types::GlobalIDType[::Projects::SavedReply],
        required: true,
        description: 'Global ID of a saved reply.'

      def resolve(id:)
        ::Projects::SavedReply.find_saved_reply(project_id: object.id, id: id.model_id)
      end
    end
  end
end
