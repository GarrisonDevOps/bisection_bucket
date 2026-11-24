# frozen_string_literal: true

module Ai
  module Catalog
    module McpServers
      class UpdateService < BaseService
        def initialize(organization:, current_user:, mcp_server:, params: {})
          super(organization: organization, current_user: current_user)
          @mcp_server = mcp_server
          @params = params
        end

        def execute
          return error('Organization context is required') unless organization

          return error('Resource is unavailable') unless Ability.allowed?(
            current_user, :update_ai_catalog_mcp_server, organization
          )

          if mcp_server.update(**params)
            send_audit_events('update_ai_catalog_mcp_server', mcp_server)
            success(mcp_server: mcp_server)
          else
            error(mcp_server.errors.full_messages)
          end
        end

        private

        attr_reader :mcp_server, :params
      end
    end
  end
end
