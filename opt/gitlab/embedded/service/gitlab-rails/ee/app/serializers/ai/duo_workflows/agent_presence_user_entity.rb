# frozen_string_literal: true

module Ai
  module DuoWorkflows
    # Adds web_path so the actor line can link the initiator the same way it does
    # with the GraphQL User type.
    class AgentPresenceUserEntity < NoteUserEntity
      expose :web_path do |user|
        user_path(user)
      end
    end
  end
end
