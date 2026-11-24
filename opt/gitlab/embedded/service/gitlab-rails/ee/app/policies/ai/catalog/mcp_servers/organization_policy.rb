# frozen_string_literal: true

module Ai
  module Catalog
    module McpServers
      module OrganizationPolicy
        extend ActiveSupport::Concern

        included do
          condition(:mcp_servers_available, scope: :user) do
            ::Ai::Catalog.mcp_servers_available?(@user)
          end

          rule { admin | organization_owner | organization_user }.policy do
            enable :read_ai_catalog_mcp_server
          end

          rule { admin | organization_owner }.policy do
            enable :create_ai_catalog_mcp_server
            enable :update_ai_catalog_mcp_server
          end

          rule { ~mcp_servers_available }.policy do
            prevent :read_ai_catalog_mcp_server
            prevent :create_ai_catalog_mcp_server
            prevent :update_ai_catalog_mcp_server
          end
        end
      end
    end
  end
end
