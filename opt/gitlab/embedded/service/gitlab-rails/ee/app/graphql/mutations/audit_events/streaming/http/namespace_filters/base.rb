# frozen_string_literal: true

module Mutations
  module AuditEvents
    module Streaming
      module HTTP
        module NamespaceFilters
          class Base < BaseMutation
            authorize :admin_external_audit_events
            include ::AuditEvents::NamespaceFilterSyncHelper

            private

            def audit(filter, action:)
              audit_context = {
                name: "#{action}_http_namespace_filter",
                author: current_user,
                scope: filter.external_audit_event_destination.group,
                target: filter.external_audit_event_destination,
                message: "#{action.capitalize} namespace filter for http audit event streaming destination " \
                         "#{filter.external_audit_event_destination.name} and namespace #{filter.namespace.full_path}"
              }

              ::Gitlab::Audit::Auditor.audit(audit_context)
            end
          end
        end
      end
    end
  end
end
