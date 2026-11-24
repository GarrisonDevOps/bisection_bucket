# frozen_string_literal: true

module Mutations
  module AuditEvents
    module Group
      module AuditEventStreamingDestinations
        class Base < BaseMutation
          authorize :admin_external_audit_events

          private

          def audit(destination, action:)
            audit_context = {
              name: "#{action}_group_audit_event_streaming_destination",
              author: current_user,
              scope: destination.group,
              target: destination.group,
              message: "#{action.capitalize} audit event streaming destination for #{destination.category.upcase}",
              additional_details: {
                category: destination.category,
                id: destination.id
              }
            }

            ::Gitlab::Audit::Auditor.audit(audit_context)
          end
        end
      end
    end
  end
end
