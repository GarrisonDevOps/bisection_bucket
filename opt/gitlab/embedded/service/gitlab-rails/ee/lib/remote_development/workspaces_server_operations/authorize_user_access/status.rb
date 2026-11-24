# frozen_string_literal: true

module RemoteDevelopment
  module WorkspacesServerOperations
    module AuthorizeUserAccess
      class Status
        INVALID_HOST = "INVALID_HOST"
        NOT_AUTHORIZED = "NOT_AUTHORIZED"
        AUTHORIZED = "AUTHORIZED"
        WORKSPACE_NOT_FOUND = "WORKSPACE_NOT_FOUND"
        PORT_NOT_FOUND = "PORT_NOT_FOUND"
      end
    end
  end
end
