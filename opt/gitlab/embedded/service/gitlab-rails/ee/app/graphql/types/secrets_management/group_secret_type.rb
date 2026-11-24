# frozen_string_literal: true

module Types
  module SecretsManagement
    class GroupSecretType < BaseObject
      graphql_name 'GroupSecret'
      description 'Represents a group secret'

      authorize :read_secret

      field :group,
        Types::GroupType,
        null: false,
        description: 'Group the secret belongs to.'

      field :name,
        type: GraphQL::Types::String,
        null: false,
        description: 'Name of the group secret.'

      field :description,
        type: GraphQL::Types::String,
        null: true,
        description: 'Description of the group secret.'

      field :environment,
        type: GraphQL::Types::String,
        null: true,
        description: "Environments that can access the secret. Null if the secret's metadata was never written."

      field :protected, GraphQL::Types::Boolean,
        null: false,
        description: 'Whether the secret is only accessible from protected branches.'

      field :rotation_info,
        type: SecretRotationInfoType,
        null: true,
        description: 'Rotation configuration for the secret.'

      field :metadata_version,
        type: GraphQL::Types::Int,
        null: true,
        description: 'Current metadata version of the group secret.'

      field :created_at,
        type: Types::TimeType,
        null: true,
        description: 'Timestamp when the secret creation started.'

      field :status, SecretStatusEnum, null: false,
        description: 'Computed lifecycle status of the secret, based on timestamps.'

      def created_at
        Time.zone.parse(object.create_started_at) if object.create_started_at.present?
      end
    end
  end
end
