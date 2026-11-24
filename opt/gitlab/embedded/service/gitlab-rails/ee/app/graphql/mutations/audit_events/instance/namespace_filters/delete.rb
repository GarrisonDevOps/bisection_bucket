# frozen_string_literal: true

module Mutations
  module AuditEvents
    module Instance
      module NamespaceFilters
        class Delete < Base
          graphql_name 'AuditEventsInstanceDestinationNamespaceFilterDelete'

          authorize_granular_token permissions: :update_audit_event_streaming_destination,
            boundary: :instance, boundary_type: :instance,
            assignable_when: [:admin]

          argument :namespace_filter_id, ::Types::GlobalIDType[::AuditEvents::Instance::NamespaceFilter],
            required: true,
            description: 'Namespace filter ID.'
          def resolve(namespace_filter_id:)
            filter = authorized_find!(id: namespace_filter_id)
            destination = filter.external_streaming_destination

            if filter.destroy
              sync_delete_legacy_namespace_filter(destination)
              audit(filter, action: :deleted)
            end

            { namespace_filter: nil, errors: filter.errors }
          end
        end
      end
    end
  end
end
