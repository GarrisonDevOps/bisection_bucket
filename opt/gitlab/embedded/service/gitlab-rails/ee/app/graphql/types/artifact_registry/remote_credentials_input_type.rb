# frozen_string_literal: true

module Types
  module ArtifactRegistry
    class RemoteCredentialsInputType < BaseInputObject
      graphql_name 'ArtifactRegistryRemoteCredentialsInput'
      description 'Upstream credentials for a remote Artifact Registry repository. Write-only: no ' \
        'field returns them.'

      argument :username, GraphQL::Types::String,
        required: false,
        validates: { allow_null: false },
        experiment: { milestone: '19.4' },
        description: 'Username for the upstream. Maven and the container formats only; pair it with ' \
          'a password.'

      argument :password, GraphQL::Types::String,
        required: false,
        validates: { allow_null: false },
        experiment: { milestone: '19.4' },
        description: 'Password for the upstream. Maven and the container formats only; pair it with ' \
          'a username.'

      argument :auth_token, GraphQL::Types::String,
        required: false,
        validates: { allow_null: false },
        experiment: { milestone: '19.4' },
        description: 'Bearer token for the upstream. npm only.'
    end
  end
end
