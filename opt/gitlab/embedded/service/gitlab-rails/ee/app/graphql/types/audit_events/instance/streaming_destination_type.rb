# frozen_string_literal: true

module Types
  module AuditEvents
    module Instance
      class StreamingDestinationType < ::Types::BaseObject
        graphql_name 'InstanceAuditEventStreamingDestination'
        description 'Represents an external destination to stream instance level audit events.'
        authorize :admin_instance_external_audit_events

        implements AuditEventStreamingDestinationInterface

        field :namespace_filters, [::Types::AuditEvents::Instance::NamespaceFilterType],
          null: true,
          description: 'List of subgroup or project filters for the destination.'
      end
    end
  end
end
