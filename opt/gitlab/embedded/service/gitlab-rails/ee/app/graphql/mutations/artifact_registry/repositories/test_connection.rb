# frozen_string_literal: true

module Mutations
  module ArtifactRegistry
    module Repositories
      # A probe that ran answers with a verdict, so an unreachable upstream is a
      # successful mutation. The error paths are Artifact Registry's 404, where the
      # route does not exist, and its 500, where the verdict could not be recorded.
      class TestConnection < Base
        graphql_name 'ArtifactRegistryRepositoryTestConnection'
        description 'Tests the upstream connection of a remote repository in Artifact Registry. Does not ' \
          'test the connection if the `artifact_registry_ui` feature flag is disabled.'

        # Artifact Registry performs the per-operation authorization check, and this
        # mutation owns no group or project to scope a token against.
        authorize_granular_token skip_reason: :external_service_authorizes

        argument :name, GraphQL::Types::String,
          required: true,
          description: 'Name of the repository to test, unique within the organization.'

        field :passed, GraphQL::Types::Boolean,
          null: true,
          description: 'Indicates the upstream answered the probe with a status below 500. Reports ' \
            'reachability rather than credential validity, so an upstream 401 or 404 passes. Null when ' \
            'no probe ran.'

        field :http_status, GraphQL::Types::Int,
          null: true,
          description: 'Status the upstream answered the probe with. Null when the probe failed in ' \
            'transport and no response arrived, and when no probe ran.'

        field :last_health_status, ::Types::ArtifactRegistry::HealthStatusEnum,
          null: true,
          description: 'Stored health verdict as it reads after the probe. Can differ from `passed`, ' \
            'because Artifact Registry moves it to `UNHEALTHY` only once consecutive failures reach its ' \
            'threshold. `UNKNOWN` when no verdict is recorded, including when this probe\'s own write did ' \
            'not land, and for a status this schema does not recognize. Null when no probe ran.'

        field :last_health_checked_at, ::Types::TimeType, # rubocop:disable GraphQL/ExtractType -- flat shape mirrors the Artifact Registry connection-test contract
          null: true,
          description: 'Timestamp of the most recent health probe of the upstream, as it reads after this ' \
            'probe. Null when no verdict is recorded, including when this probe\'s own write did not land.'

        def resolve_artifact_registry(name:)
          result = artifact_registry_client.test_upstream_connection(
            slug: artifact_registry_slug,
            name: name
          )
          stored_status = ::Types::ArtifactRegistry::HealthStatusEnum.recognized_or_unknown(result.last_health_status)

          {
            passed: result.passed,
            http_status: result.http_status,
            last_health_status: stored_status,
            last_health_checked_at: result.last_health_checked_at
          }
        end
      end
    end
  end
end
