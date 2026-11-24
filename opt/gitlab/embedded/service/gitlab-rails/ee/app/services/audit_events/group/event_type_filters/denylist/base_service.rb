# frozen_string_literal: true

module AuditEvents
  module Group
    module EventTypeFilters
      module Denylist
        class BaseService
          attr_reader :destination, :event_type_filters, :current_user

          def initialize(destination:, event_type_filters:, current_user:)
            @destination = destination
            @event_type_filters = event_type_filters
            @current_user = current_user
          end

          private

          def log_audit_event(name:, message:)
            audit_context = {
              name: name,
              author: current_user,
              scope: destination.group,
              target: destination,
              message: "#{message}: #{event_type_filters.to_sentence}"
            }

            ::Gitlab::Audit::Auditor.audit(audit_context)
          end
        end
      end
    end
  end
end
