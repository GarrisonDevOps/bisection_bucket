# frozen_string_literal: true

module AuditEvents
  module Streaming
    module Headers
      class Base < ::BaseGroupService
        include AuditEvents::Streaming::HeadersOperations

        attr_reader :destination

        def initialize(destination:, current_user: nil, params: {})
          @destination = destination

          super(
            group: @destination&.group,
            current_user: current_user,
            params: params
          )
        end

        def execute
          destination_error if destination.blank?
        end

        private

        def destination_error
          ServiceResponse.error(message: "missing destination param")
        end

        def audit(action:, header:, message:, author: current_user, additional_details: {})
          audit_context = {
            name: "audit_events_streaming_headers_#{action}",
            author: author,
            scope: group,
            target: header,
            target_details: header.key,
            message: message,
            stream_only: false,
            additional_details: additional_details
          }

          ::Gitlab::Audit::Auditor.audit(audit_context)
        end
      end
    end
  end
end
