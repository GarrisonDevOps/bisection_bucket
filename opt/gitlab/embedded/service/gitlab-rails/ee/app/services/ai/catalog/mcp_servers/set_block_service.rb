# frozen_string_literal: true

module Ai
  module Catalog
    module McpServers
      # Blocks or allows an external MCP server for a group or project (kill-switch). The container is
      # a Group or a Project; a project block is stored against the project's project-namespace so it
      # resolves uniformly with group blocks. A block applies to the container and its descendants;
      # allowing removes the container's own block record.
      class SetBlockService
        def initialize(container:, mcp_server:, current_user:, blocked:)
          @container = container
          @mcp_server = mcp_server
          @current_user = current_user
          @blocked = blocked
        end

        def execute
          return error('You have insufficient permissions') unless allowed?
          return error('MCP server does not belong to this organization') unless same_organization?

          # Both writes are idempotent, so audit only a real state change: re-blocking or allowing
          # twice would otherwise leave phantom entries in the compliance log.
          state_changed = blocked ? create_block : remove_block
          send_audit_event if state_changed

          ServiceResponse.success(payload: { mcp_server: mcp_server })
        end

        private

        attr_reader :container, :mcp_server, :current_user, :blocked

        def allowed?
          Ability.allowed?(current_user, :block_ai_catalog_mcp_server, container)
        end

        def same_organization?
          container.organization_id == mcp_server.organization_id
        end

        # Project blocks are keyed on the project-namespace so the shared ancestry resolution treats
        # them uniformly with group blocks.
        def block_namespace
          container.is_a?(::Project) ? container.project_namespace : container
        end

        def create_block
          ::Ai::Catalog::McpServerBlock.block!(
            namespace: block_namespace, mcp_server: mcp_server, created_by: current_user
          ).previously_new_record?
        end

        def remove_block
          ::Ai::Catalog::McpServerBlock.unblock!(namespace: block_namespace, mcp_server: mcp_server) > 0
        end

        def send_audit_event
          event_name, verb =
            blocked ? %w[block_ai_catalog_mcp_server Blocked] : %w[unblock_ai_catalog_mcp_server Allowed]

          ::Gitlab::Audit::Auditor.audit(
            name: event_name,
            author: current_user,
            scope: container,
            target: mcp_server,
            target_details: "#{mcp_server.name} (ID: #{mcp_server.id})",
            message: "#{verb} MCP server (URL: #{mcp_server.url})"
          )
        end

        def error(message)
          ServiceResponse.error(message: Array(message))
        end
      end
    end
  end
end
