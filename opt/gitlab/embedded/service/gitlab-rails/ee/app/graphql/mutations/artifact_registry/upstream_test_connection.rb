# frozen_string_literal: true

module Mutations
  module ArtifactRegistry
    class UpstreamTestConnection < Base
      graphql_name 'ArtifactRegistryUpstreamTestConnection'
      description 'Tests a supplied upstream connection for the remote repository create form in ' \
        'Artifact Registry, before any repository exists to hold it. Does not test the connection if ' \
        'the `artifact_registry_ui` feature flag is disabled.'

      # Artifact Registry performs the per-operation authorization check, and this
      # mutation owns no group or project to scope a token against.
      authorize_granular_token skip_reason: :external_service_authorizes

      argument :format, ::Types::ArtifactRegistry::RepositoryFormatEnum,
        required: true,
        description: 'Package format of the upstream to probe. Decides the credential shape and the probe auth.'

      argument :url, GraphQL::Types::String,
        required: true,
        description: 'Base URL of the upstream to probe.'

      argument :credentials, ::Types::ArtifactRegistry::RemoteCredentialsInputType,
        required: false,
        description: 'Upstream credentials to probe with. Omit or pass null to probe unauthenticated. ' \
          'Accepted for every format, but ignored when probing a container upstream (docker or oci), ' \
          'whose probe is always unauthenticated.'

      field :passed, GraphQL::Types::Boolean,
        null: true,
        description: 'Indicates the upstream answered the probe with a status below 500. Reports ' \
          'reachability rather than credential validity, so an upstream 401 or 404 passes. Null when ' \
          'no probe ran.'

      field :http_status, GraphQL::Types::Int,
        null: true,
        description: 'Status the upstream answered the probe with. Null when the probe failed in ' \
          'transport and no response arrived, and when no probe ran.'

      def resolve_artifact_registry(format:, url:, credentials: nil)
        result = artifact_registry_client.test_namespace_upstream_connection(
          slug: artifact_registry_slug,
          format: format,
          url: url,
          credentials: credentials&.to_h&.presence
        )

        { passed: result.passed, http_status: result.http_status }
      end
    end
  end
end
