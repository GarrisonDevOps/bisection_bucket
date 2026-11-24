# frozen_string_literal: true

module Mutations
  module AuditEvents
    module Group
      module NamespaceFilters
        class Delete < Base
          graphql_name 'AuditEventsGroupDestinationNamespaceFilterDelete'

          authorize_granular_token permissions: :update_audit_event_streaming_destination,
            boundary_argument: :namespace_filter_id, boundary: :group, boundary_type: :group

          argument :namespace_filter_id, ::Types::GlobalIDType[::AuditEvents::Group::NamespaceFilter],
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
