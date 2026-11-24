# frozen_string_literal: true

module Mutations
  module AuditEvents
    module Streaming
      module HTTP
        module NamespaceFilters
          class Delete < Base
            graphql_name 'AuditEventsStreamingHTTPNamespaceFiltersDelete'

            authorize_granular_token permissions: :update_audit_event_streaming_destination,
              boundary_argument: :namespace_filter_id, boundary: :group, boundary_type: :group

            argument :namespace_filter_id, ::Types::GlobalIDType[::AuditEvents::Streaming::HTTP::NamespaceFilter],
              required: true,
              description: 'Namespace filter ID.'

            def resolve(namespace_filter_id:)
              filter = authorized_find!(id: namespace_filter_id)

              destination = filter.external_audit_event_destination
              should_sync = destination.stream_destination_id.present?

              if filter.destroy
                sync_delete_stream_namespace_filter(destination) if should_sync
                audit(filter, action: :delete)
              end

              { namespace_filter: nil, errors: [] }
            end

            private

            def find_object(id:)
              ::GitlabSchema.object_from_id(id, expected_type: ::AuditEvents::Streaming::HTTP::NamespaceFilter)
            end
          end
        end
      end
    end
  end
end
