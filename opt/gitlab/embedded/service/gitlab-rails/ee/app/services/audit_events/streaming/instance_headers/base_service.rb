# frozen_string_literal: true

module AuditEvents
  module Streaming
    module InstanceHeaders
      class BaseService
        include AuditEvents::Streaming::HeadersOperations

        attr_reader :params, :current_user

        def initialize(params: {}, current_user: nil)
          @params = params
          @current_user = current_user
        end

        def audit(action:, header:, message:, author: current_user, additional_details: {})
          audit_context = {
            name: "audit_events_streaming_instance_headers_#{action}",
            author: author,
            scope: Gitlab::Audit::InstanceScope.new,
            target: header,
            target_details: header.key,
            message: message,
            additional_details: additional_details
          }

          ::Gitlab::Audit::Auditor.audit(audit_context)
        end
      end
    end
  end
end
