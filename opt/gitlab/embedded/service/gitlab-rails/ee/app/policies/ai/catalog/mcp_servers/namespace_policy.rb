# frozen_string_literal: true

module Ai
  module Catalog
    module McpServers
      module NamespacePolicy
        extend ActiveSupport::Concern

        included do
          condition(:mcp_servers_available, scope: :user) do
            ::Ai::Catalog.mcp_servers_available?(@user)
          end

          with_scope :subject
          condition(:duo_workflow_mcp_enabled) do
            @subject.root_ancestor.duo_workflow_mcp_enabled
          end

          rule { can?(:read_ai_catalog_item_consumer) & duo_workflow_mcp_enabled }.policy do
            enable :read_ai_catalog_mcp_server
          end

          rule { ~mcp_servers_available }.policy do
            prevent :read_ai_catalog_mcp_server
          end
        end
      end
    end
  end
end
