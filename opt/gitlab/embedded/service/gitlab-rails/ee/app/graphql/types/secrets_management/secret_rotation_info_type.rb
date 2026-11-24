# frozen_string_literal: true

# rubocop: disable Graphql/AuthorizeTypes -- Authorization is handled in the parent type (ProjectSecretType/GroupSecretType)
module Types
  module SecretsManagement
    class SecretRotationInfoType < BaseObject
      graphql_name 'SecretRotationInfo'
      description 'Rotation configuration and status for a secret.'

      field :rotation_interval_days, GraphQL::Types::Int, null: false,
        description: 'Number of days between rotation reminders.'

      field :status, SecretRotationStatusEnum, null: false,
        description: 'Current rotation status.'

      field :next_reminder_at, Types::TimeType, null: false,
        description: 'When the next rotation reminder will be sent.'

      field :last_reminder_at, Types::TimeType, null: true,
        description: 'When the last rotation reminder was sent.'

      field :updated_at, Types::TimeType, null: false,
        description: 'When the rotation configuration was last updated.'

      field :created_at, Types::TimeType, null: false,
        description: 'When the rotation configuration was created.'
    end
  end
end
# rubocop: enable Graphql/AuthorizeTypes
