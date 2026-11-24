# frozen_string_literal: true

module Mutations
  module AuditEvents
    module Instance
      module NamespaceFilters
        # rubocop:disable GraphQL/GraphqlName -- This is a base mutation so name is not needed here
        class Base < BaseMutation
          authorize :admin_instance_external_audit_events
          include ::AuditEvents::NamespaceFilterSyncHelper

          private

          def audit(filter, action:)
            audit_context = {
              name: "#{action}_instance_namespace_filter",
              author: current_user,
              scope: Gitlab::Audit::InstanceScope.new,
              target: filter.external_streaming_destination,
              message: "#{action.capitalize} namespace filter for instance audit event streaming destination.",
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
# rubocop:enable GraphQL/GraphqlName
