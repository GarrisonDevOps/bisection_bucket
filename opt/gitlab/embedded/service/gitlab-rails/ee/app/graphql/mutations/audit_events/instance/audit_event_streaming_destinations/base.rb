# frozen_string_literal: true

module Mutations
  module AuditEvents
    module Instance
      module AuditEventStreamingDestinations
        class Base < BaseMutation
          authorize :admin_instance_external_audit_events

          def ready?(**args)
            unless Ability.allowed?(current_user, :admin_instance_external_audit_events)
              raise_resource_not_available_error!
            end

            super
          end

          private

          def audit(destination, action:)
            audit_context = {
              name: "#{action}_instance_audit_event_streaming_destination",
              author: current_user,
              scope: Gitlab::Audit::InstanceScope.new,
              target: destination,
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
