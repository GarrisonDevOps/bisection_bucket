# frozen_string_literal: true

module Ai
  class DeleteConversationThreadService
    include ::Gitlab::Allowable

    def initialize(current_user:)
      @current_user = current_user
    end

    def execute(thread)
      return unauthorized_response unless can_delete?(thread)

      if thread.destroy
        ::ServiceResponse.success
      else
        ::ServiceResponse.error(message: thread.errors.full_messages)
      end
    end

    private

    def can_delete?(thread)
      can?(@current_user, :delete_conversation_thread, thread)
    end

    def unauthorized_response
      ::ServiceResponse.error(message: 'User not authorized to delete thread')
    end
  end
end
