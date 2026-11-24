# frozen_string_literal: true

module Mutations
  module AuditEvents
    module Group
      module NamespaceFilters
        class Base < BaseMutation
          authorize :admin_external_audit_events
          include ::AuditEvents::NamespaceFilterSyncHelper

          private

          def audit(filter, action:)
            audit_context = {
              name: "#{action}_group_namespace_filter",
              author: current_user,
              scope: filter.external_streaming_destination.group,
              target: filter.external_streaming_destination,
              message: "#{action.capitalize} namespace filter for group audit event streaming destination.",
              additional_details: {
                destination_name: filter.external_streaming_destination.name,
                namespace: filter.namespace.full_path
              }
            }

            ::Gitlab::Audit::Auditor.audit(audit_context)
          end
        end
      end
    end
  end
end
