# frozen_string_literal: true

module Types
  module AuditEvents
    module Streaming
      module HTTP
        class NamespaceFilterType < ::Types::BaseObject
          graphql_name 'AuditEventStreamingHTTPNamespaceFilter'

          description 'Represents a subgroup or project filter that belongs to ' \
                      'an external audit event streaming destination.'

          authorize :admin_external_audit_events

          field :id, GraphQL::Types::ID,
            null: false,
            description: 'ID of the filter.'

          field :namespace, ::Types::NamespaceType,
            null: false,
            description: 'Group or project namespace the filter belongs to.'

          field :external_audit_event_destination, ::Types::AuditEvents::ExternalAuditEventDestinationType,
            null: false,
            description: 'Destination to which the filter belongs.'
        end
      end
    end
  end
end
