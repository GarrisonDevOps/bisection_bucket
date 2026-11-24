# frozen_string_literal: true

module Ai
  module Catalog
    module McpServers
      class BaseService
        include BaseServiceUtility

        def initialize(organization:, current_user:)
          @organization = organization
          @current_user = current_user
        end

        private

        attr_reader :organization, :current_user

        def send_audit_events(event_type, mcp_server)
          messages = AuditEventMessageService.new(event_type, mcp_server).messages

          messages.each do |message|
            audit_context = {
              name: event_type,
              author: current_user,
              scope: ::Gitlab::Audit::InstanceScope.new,
              target: mcp_server,
              target_details: "#{mcp_server.name} (ID: #{mcp_server.id})",
              message: message
            }

            ::Gitlab::Audit::Auditor.audit(audit_context)
          end
        end

        def success(payload)
          ServiceResponse.success(payload: payload)
        end

        def error(message)
          ServiceResponse.error(message: Array(message))
        end
      end
    end
  end
end
