# frozen_string_literal: true

module Types
  module AuditEvents
    module Instance
      class NamespaceFilterType < ::Types::BaseObject
        graphql_name 'InstanceAuditEventNamespaceFilter'
        description 'Represents a subgroup or project filter that belongs to ' \
          'an instance level external audit event streaming destination.'
        authorize :admin_instance_external_audit_events

        field :id, GraphQL::Types::ID,
          null: false,
          description: 'ID of the filter.'

        field :namespace, ::Types::NamespaceType,
          null: false,
          description: 'Group or project namespace the filter belongs to.'

        field :external_streaming_destination, ::Types::AuditEvents::Instance::StreamingDestinationType,
          null: false,
          description: 'Destination to which the filter belongs.'
      end
    end
  end
end
