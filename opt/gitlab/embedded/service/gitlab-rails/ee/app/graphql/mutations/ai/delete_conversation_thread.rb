# frozen_string_literal: true

module Mutations
  module Ai
    class DeleteConversationThread < BaseMutation
      graphql_name 'DeleteConversationThread'

      authorize :delete_conversation_thread
      authorize_granular_token permissions: :delete_conversation_thread,
        boundary: :user, boundary_type: :user

      field :success, GraphQL::Types::Boolean,
        null: false,
        description: 'Returns true if thread was successfully deleted.'

      field :errors, [GraphQL::Types::String],
        null: false,
        description: 'List of errors that occurred whilst trying to delete the thread.'

      argument :thread_id, ::Types::GlobalIDType[::Ai::Conversation::Thread],
        required: true,
        description: 'Global ID of the thread to delete.'

      def resolve(thread_id:)
        thread = authorized_find!(id: thread_id)

        result = ::Ai::DeleteConversationThreadService.new(
          current_user: current_user
        ).execute(thread)

        {
          success: result.success?,
          errors: result.success? ? [] : Array(result.message)
        }
      end
    end
  end
end
