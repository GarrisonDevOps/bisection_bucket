# frozen_string_literal: true

module Mutations
  module AuditEvents
    module Group
      module AuditEventStreamingDestinations
        class Delete < Base
          graphql_name 'GroupAuditEventStreamingDestinationsDelete'

          authorize_granular_token permissions: :delete_audit_event_streaming_destination,
            boundary_argument: :id, boundary: :group, boundary_type: :group

          argument :id, ::Types::GlobalIDType[::AuditEvents::Group::ExternalStreamingDestination],
            required: true,
            description: 'ID of the audit events external streaming destination to delete.'

          def resolve(id:)
            config = authorized_find!(id: id)
            paired_destination = config.legacy_destination
            if config.destroy
              audit(config, action: :deleted)

              paired_destination&.destroy
            end

            { errors: Array(config.errors) }
          end
        end
      end
    end
  end
end
