# frozen_string_literal: true

module AuditEvents
  module Streaming
    module EventTypeFilters
      class BaseService
        include ::AuditEvents::EventFilterSyncHelper

        attr_reader :destination, :event_type_filters, :current_user, :model

        def initialize(destination:, event_type_filters:, current_user:)
          @destination = destination
          @event_type_filters = event_type_filters
          @current_user = current_user
          @model = model_of_destination(destination)
        end

        private

        def model_of_destination(destination)
          case destination
          when AuditEvents::InstanceExternalAuditEventDestination
            ::AuditEvents::Streaming::InstanceEventTypeFilter
          when AuditEvents::Group::ExternalStreamingDestination
            ::AuditEvents::Group::EventTypeFilter
          when AuditEvents::Instance::ExternalStreamingDestination
            ::AuditEvents::Instance::EventTypeFilter
          else
            ::AuditEvents::Streaming::EventTypeFilter
          end
        end

        def log_audit_event(name:, message:)
          audit_context = {
            name: name,
            author: current_user,
            scope: get_audit_scope,
            target: destination,
            message: "#{message}: #{event_type_filters.to_sentence}"
          }

          ::Gitlab::Audit::Auditor.audit(audit_context)
        end

        def get_audit_scope
          if destination.is_a?(AuditEvents::InstanceExternalAuditEventDestination) ||
              destination.is_a?(AuditEvents::Instance::ExternalStreamingDestination)
            Gitlab::Audit::InstanceScope.new
          else
            destination.group
          end
        end
      end
    end
  end
end
