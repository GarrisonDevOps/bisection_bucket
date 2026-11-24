# frozen_string_literal: true

module Ai
  module Catalog
    module McpServers
      class CreateService < BaseService
        def initialize(organization:, current_user:, params: {})
          super(organization: organization, current_user: current_user)
          @params = params
        end

        def execute
          return error('Organization context is required') unless organization

          return error('Resource is unavailable') unless Ability.allowed?(
            current_user, :create_ai_catalog_mcp_server, organization
          )

          mcp_server = ::Ai::Catalog::McpServer.new(
            organization: organization,
            created_by: current_user,
            **params
          )

          if mcp_server.save
            send_audit_events('create_ai_catalog_mcp_server', mcp_server)
            success(mcp_server: mcp_server)
          else
            error(mcp_server.errors.full_messages)
          end
        end

        private

        attr_reader :params
      end
    end
  end
end
