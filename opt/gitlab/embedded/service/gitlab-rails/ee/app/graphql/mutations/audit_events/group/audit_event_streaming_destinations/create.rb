# frozen_string_literal: true

module Mutations
  module AuditEvents
    module Group
      module AuditEventStreamingDestinations
        class Create < Base
          graphql_name 'GroupAuditEventStreamingDestinationsCreate'

          authorize_granular_token permissions: :create_audit_event_streaming_destination,
            boundary_argument: :group_path, boundary_type: :group
          include ::AuditEvents::StreamDestinationSyncHelper
          include ::Mutations::AuditEvents::DestinationRateLimitable

          argument :config, GraphQL::Types::JSON, # rubocop:disable Graphql/JSONType -- Different type of destinations will have different configs
            required: true,
            description: 'Destination config.'

          argument :name, GraphQL::Types::String,
            required: false,
            description: 'Destination name.'

          argument :category, GraphQL::Types::String,
            required: true,
            description: 'Destination category.'

          argument :group_path, GraphQL::Types::ID,
            required: true,
            description: 'Group path.'

          argument :secret_token, GraphQL::Types::String,
            required: false,
            description: 'Secret token.'

          field :external_audit_event_destination, ::Types::AuditEvents::Group::StreamingDestinationType,
            null: true,
            description: 'Destination created.'

          def resolve(group_path:, secret_token: nil, name: nil, category: nil, config: nil)
            group = authorized_find!(group_path)
            return destination_rate_limited_response if destination_rate_limited?(group)

            unless validate_secret_token(category, secret_token)
              return {
                errors: ["Secret token is required for category"]
              }
            end

            destination = ::AuditEvents::Group::ExternalStreamingDestination.new(group: group,
              secret_token: secret_token,
              name: name,
              config: config,
              category: category
            )

            if destination.save
              audit(destination, action: :created)
              create_legacy_destination(destination)
            end

            {
              external_audit_event_destination: (destination if destination.persisted?),
              errors: Array(destination.errors)
            }
          end

          private

          def find_object(group_path)
            ::Group.find_by_full_path(group_path)
          end

          def validate_secret_token(category, secret_token)
            category == 'http' || secret_token.present?
          end
        end
      end
    end
  end
end
