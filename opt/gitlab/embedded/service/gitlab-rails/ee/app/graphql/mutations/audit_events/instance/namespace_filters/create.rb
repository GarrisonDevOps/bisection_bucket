# frozen_string_literal: true

module Mutations
  module AuditEvents
    module Instance
      module NamespaceFilters
        class Create < Base
          graphql_name 'AuditEventsInstanceDestinationNamespaceFilterCreate'

          authorize_granular_token permissions: :update_audit_event_streaming_destination,
            boundary: :instance, boundary_type: :instance,
            assignable_when: [:admin]

          argument :destination_id, ::Types::GlobalIDType[::AuditEvents::Instance::ExternalStreamingDestination],
            required: true,
            description: 'Destination ID.'

          argument :namespace_path, GraphQL::Types::String,
            required: false,
            description: 'Full path of the namespace. Project or group namespaces only.'

          field :namespace_filter, ::Types::AuditEvents::Instance::NamespaceFilterType,
            null: true,
            description: 'Namespace filter to be created.'

          def resolve(args)
            destination = authorized_find!(args[:destination_id])

            namespace = namespace(args[:namespace_path])
            filter = ::AuditEvents::Instance::NamespaceFilter.new(external_streaming_destination: destination,
              namespace: namespace)

            if destination.with_lock { filter.save }
              sync_legacy_namespace_filter(destination, namespace)
              audit(filter, action: :created)
            end

            { namespace_filter: (filter if filter.persisted?), errors: Array(filter.errors) }
          end

          private

          def find_object(destination_id)
            ::GitlabSchema.object_from_id(destination_id,
              expected_type: ::AuditEvents::Instance::ExternalStreamingDestination)
          end

          def namespace(namespace_path)
            namespace = Routable.find_by_full_path(namespace_path)

            case namespace
            when ::Group
              namespace
            when ::Project
              namespace.project_namespace
            else
              raise Gitlab::Graphql::Errors::ArgumentError, "namespace_path should be of group or project only."
            end
          end
        end
      end
    end
  end
end
