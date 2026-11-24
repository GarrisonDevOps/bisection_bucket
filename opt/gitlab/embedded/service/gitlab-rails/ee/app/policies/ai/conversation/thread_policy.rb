# frozen_string_literal: true

module Ai
  module Conversation
    class ThreadPolicy < BasePolicy
      desc 'User is owner of the thread'
      condition(:owner) do
        @user && @user == @subject.user
      end

      rule { owner }.enable :delete_conversation_thread
    end
  end
end
