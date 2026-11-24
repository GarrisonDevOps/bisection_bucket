# frozen_string_literal: true

module Mutations
  module AuditEvents
    module Group
      module NamespaceFilters
        class Create < Base
          graphql_name 'AuditEventsGroupDestinationNamespaceFilterCreate'

          authorize_granular_token permissions: :update_audit_event_streaming_destination,
            boundary_argument: :destination_id, boundary: :group, boundary_type: :group

          argument :destination_id, ::Types::GlobalIDType[::AuditEvents::Group::ExternalStreamingDestination],
            required: true,
            description: 'Destination ID.'

          argument :namespace_path, GraphQL::Types::String,
            required: false,
            description: 'Full path of the namespace(only project or group).'

          field :namespace_filter, ::Types::AuditEvents::Group::NamespaceFilterType,
            null: true,
            description: 'Namespace filter created.'

          def resolve(args)
            destination = authorized_find!(args[:destination_id])

            namespace = namespace(args[:namespace_path])

            filter = ::AuditEvents::Group::NamespaceFilter.new(
              external_streaming_destination: destination,
              namespace: namespace
            )

            if destination.with_lock { filter.save }
              sync_legacy_namespace_filter(destination, namespace)
              audit(filter, action: :created)
            end

            { namespace_filter: (filter if filter.persisted?), errors: Array(filter.errors) }
          end

          private

          def find_object(destination_id)
            ::GitlabSchema.object_from_id(destination_id,
              expected_type: ::AuditEvents::Group::ExternalStreamingDestination)
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
