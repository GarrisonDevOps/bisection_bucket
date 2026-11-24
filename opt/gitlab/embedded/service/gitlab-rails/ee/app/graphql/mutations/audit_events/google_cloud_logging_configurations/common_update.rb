# frozen_string_literal: true

module Mutations
  module AuditEvents
    module GoogleCloudLoggingConfigurations
      module CommonUpdate
        extend ActiveSupport::Concern
        include ::AuditEvents::LegacyDestinationSyncHelper

        AUDIT_EVENT_COLUMNS = [:google_project_id_name, :client_email, :private_key, :log_id_name, :name,
          :active].freeze

        included do
          include ::AuditEvents::Changes

          argument :name, GraphQL::Types::String,
            required: false,
            description: 'Destination name.'

          argument :google_project_id_name, GraphQL::Types::String,
            required: false,
            description: 'Unique identifier of the Google Cloud project ' \
                         'to which the logging configuration belongs.'

          argument :client_email, GraphQL::Types::String,
            required: false,
            description: 'Email address associated with the service account ' \
                         'that will be used to authenticate and interact with the ' \
                         'Google Cloud Logging service. This is part of the IAM credentials.'

          argument :log_id_name, GraphQL::Types::String,
            required: false,
            description: 'Unique identifier used to distinguish and manage ' \
                         'different logs within the same Google Cloud project.'

          argument :private_key, GraphQL::Types::String,
            required: false,
            description: 'Private Key associated with the service account. This key ' \
                         'is used to authenticate the service account and authorize it ' \
                         'to interact with the Google Cloud Logging service.'

          argument :active, GraphQL::Types::Boolean,
            required: false,
            description: 'Active status of the destination.'
        end

        def update_config(
          id:, config: nil,
          google_project_id_name: nil, client_email: nil, private_key: nil, log_id_name: nil, name: nil, active: nil
        )
          config ||= authorized_find!(id)

          config_attributes = {
            google_project_id_name: google_project_id_name,
            client_email: client_email,
            private_key: private_key,
            log_id_name: log_id_name,
            name: name,
            active: active
          }.compact

          if config.update(config_attributes)
            audit_update(config)
            update_stream_destination(legacy_destination_model: config)
            [config, []]
          else
            [nil, Array(config.errors)]
          end
        end

        private

        def audit_update(destination)
          event_name = self.class::UPDATE_EVENT_NAME
          AUDIT_EVENT_COLUMNS.each do |column|
            next unless destination.saved_change_to_attribute?(column)

            audit_changes(
              column,
              as: column.to_s,
              entity: entity_for_model(destination),
              model: destination,
              event_type: event_name
            )
          end
        end

        def entity_for_model(config)
          if config.is_a?(::AuditEvents::Instance::GoogleCloudLoggingConfiguration)
            Gitlab::Audit::InstanceScope.new
          else
            config.group
          end
        end
      end
    end
  end
end
