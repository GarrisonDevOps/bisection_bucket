# frozen_string_literal: true

module EE
  module API
    module Helpers
      module McpHelpers
        # Checks if the current request is using MCP (Model Context Protocol) scope
        #
        # @return [Boolean] true if the request has MCP scope, false otherwise
        def mcp_request?
          return false unless access_token

          AccessTokenValidationService.new(access_token).include_any_scope?([::Gitlab::Auth::MCP_SCOPE])
        end
      end
    end
  end
end
