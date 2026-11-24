# frozen_string_literal: true

module Types
  module Geo
    module RegistryType
      extend ActiveSupport::Concern

      included do
        authorize :read_geo_registry
        authorize_granular_token permissions: :read_geo_registry, boundary: :instance, boundary_type: :instance,
          assignable_when: [:admin]
        connection_type_class Types::LimitedCountableConnectionType

        field :checksum_mismatch, GraphQL::Types::Boolean, null: true, description: "Indicate if the checksums of the #{graphql_name} do not match on the primary and secondary."
        field :created_at, Types::TimeType, null: true, description: "Timestamp when the #{graphql_name} was created"
        field :data_management_details_path, GraphQL::Types::String, null: true, description: "Path to the data management view for this #{graphql_name}"
        field :force_to_redownload,
          GraphQL::Types::Boolean,
          null: true,
          fallback_value: nil,
          description: "Indicate if a forced redownload is to be performed.",
          deprecated: { reason: 'Removed from registry tables in the database in favor of the newer reusable framework', milestone: '17.10' }
        field :id, GraphQL::Types::ID, null: false, description: "ID of the #{graphql_name}"
        field :last_sync_failure, GraphQL::Types::String, null: true, description: "Error message during sync of the #{graphql_name}"
        field :last_synced_at, Types::TimeType, null: true, description: "Timestamp of the most recent successful sync of the #{graphql_name}"
        field :missing_on_primary, GraphQL::Types::Boolean, null: true, fallback_value: nil, description: "Indicate if the #{graphql_name} is missing on primary."
        field :model_record_id, GraphQL::Types::Int, null: true, description: "ID of the #{graphql_name}'s model record."
        field :retry_at, Types::TimeType, null: true, description: "Timestamp after which the #{graphql_name} is resynced"
        field :retry_count, GraphQL::Types::Int, null: true, description: "Number of consecutive failed sync attempts of the #{graphql_name}"
        field :state, Types::Geo::RegistryStateEnum, null: true, method: :state_name, description: "Sync state of the #{graphql_name}"
        field :verification_checksum, GraphQL::Types::String, null: true, description: "The local checksum of the #{graphql_name}"
        field :verification_checksum_mismatched, GraphQL::Types::String, null: true, description: "The expected checksum of the #{graphql_name} in case of mismatch."
        field :verification_failure, GraphQL::Types::String, null: true, description: "Error message during verification of the #{graphql_name}"
        field :verification_retry_at, Types::TimeType, null: true, description: "Timestamp after which the #{graphql_name} is reverified"
        field :verification_retry_count, GraphQL::Types::Int, null: true, description: "Number of consecutive failed verification attempts of the #{graphql_name}"
        field :verification_started_at, Types::TimeType, null: true, description: "Timestamp when the verification of #{graphql_name} started"
        field :verification_state, Types::Geo::VerificationStateEnum, null: true, resolver_method: :verification_state_name_value, description: "Verification state of the #{graphql_name}"
        field :verified_at, Types::TimeType, null: true, description: "Timestamp of the most recent successful verification of the #{graphql_name}"

        def verification_state_name_value
          object.verification_state_name_no_prefix
        end

        def data_management_details_path
          return unless object.model_record_id

          ::Gitlab::Routing.url_helpers.details_admin_data_management_path(
            model_name: object.class.replicator_class.model_name_plural,
            id: object.model_record_id
          )
        end
      end
    end
  end
end
