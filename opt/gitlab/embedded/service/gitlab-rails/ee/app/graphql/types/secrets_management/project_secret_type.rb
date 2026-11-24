# frozen_string_literal: true

module Types
  module SecretsManagement
    class ProjectSecretType < BaseObject
      graphql_name 'ProjectSecret'
      description 'Representation of a project secret.'

      authorize :read_project_secrets

      field :project,
        Types::ProjectType,
        null: false,
        description: 'Project the secret belongs to.'

      field :name,
        type: GraphQL::Types::String,
        null: false,
        description: 'Name of the project secret.'

      field :description,
        type: GraphQL::Types::String,
        null: true,
        description: 'Description of the project secret.'

      field :environment,
        type: GraphQL::Types::String,
        null: true,
        description: "Environments that can access the secret. Null if the secret's metadata was never written."

      field :branch,
        type: GraphQL::Types::String,
        null: true,
        description: "Branches that can access the secret. Null if the secret's metadata was never written."

      field :rotation_info,
        type: SecretRotationInfoType,
        null: true,
        description: 'Rotation configuration for the secret.'

      field :metadata_version,
        type: GraphQL::Types::Int,
        null: true,
        description: 'Current metadata version of the project secret.'

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
