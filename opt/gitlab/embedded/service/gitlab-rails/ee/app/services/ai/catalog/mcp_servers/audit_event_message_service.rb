# frozen_string_literal: true

module Ai
  module Catalog
    module McpServers
      class AuditEventMessageService
        def initialize(event_type, mcp_server, params = {})
          @event_type = event_type
          @mcp_server = mcp_server
          @params = params
        end

        def messages
          case event_type
          when 'create_ai_catalog_mcp_server'
            create_messages
          when 'update_ai_catalog_mcp_server'
            update_messages
          else
            []
          end
        end

        private

        attr_reader :event_type, :mcp_server, :params

        def create_messages
          ["Created MCP server (URL: #{mcp_server.url})"]
        end

        def update_messages
          descriptions = build_change_descriptions

          if descriptions.any?
            ["Updated MCP server: #{descriptions.join(', ')}"]
          else
            ["Updated MCP server"]
          end
        end

        def build_change_descriptions
          descriptions = []
          changes = mcp_server.previous_changes

          descriptions << "Name changed to '#{mcp_server.name}'" if changes.key?('name')
          descriptions << "URL changed to '#{mcp_server.url}'" if changes.key?('url')
          descriptions << "Description updated" if changes.key?('description')
          descriptions << "Transport changed to '#{mcp_server.transport}'" if changes.key?('transport')
          descriptions << "Auth type changed to '#{mcp_server.auth_type}'" if changes.key?('auth_type')

          descriptions
        end
      end
    end
  end
end
