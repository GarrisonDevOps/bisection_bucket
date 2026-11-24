# frozen_string_literal: true

module Types
  module ArtifactRegistry
    class RemoteSettingsType < BaseObject
      graphql_name 'ArtifactRegistryRemoteSettings'
      description 'Upstream configuration of a remote Artifact Registry repository.'

      authorize :read_artifact_registry

      include ::ArtifactRegistry::TimeCoercion

      # Reachable only through the repository field, which authorizes against the organization.
      authorize_granular_token skip_reason: :parent_authorizes

      field :url, GraphQL::Types::String,
        null: true,
        experiment: { milestone: '19.4' },
        description: 'Base URL of the upstream registry, in the canonical form Artifact Registry stores.'

      field :cache_validity_hours, GraphQL::Types::Int,
        null: true,
        experiment: { milestone: '19.4' },
        description: 'Revalidation window for cached artifacts, in hours. Zero means cached artifacts ' \
          'never revalidate.'

      field :metadata_cache_validity_hours, GraphQL::Types::Int,
        null: true,
        experiment: { milestone: '19.4' },
        description: 'Revalidation window for cached metadata, in hours. Null for a format that caches ' \
          'no metadata, such as Docker and OCI.'

      field :snapshot_metadata_always_revalidate, GraphQL::Types::Boolean,
        null: true,
        experiment: { milestone: '19.4' },
        description: 'Indicates snapshot metadata revalidates on every read instead of on the metadata ' \
          'window. Null for a format without snapshot metadata, so non-null only for Maven.'

      field :has_credentials, GraphQL::Types::Boolean,
        null: true,
        experiment: { milestone: '19.4' },
        description: 'Indicates upstream credentials are stored. Reported in place of the credentials ' \
          'themselves, which are write-only and exposed by no field.'

      field :credentials_cleared, GraphQL::Types::Boolean,
        null: true,
        experiment: { milestone: '19.4' },
        description: 'Indicates the update that returned this repository cleared the stored upstream ' \
          'credentials. Null on any other response.'

      field :last_health_status, ::Types::ArtifactRegistry::HealthStatusEnum,
        null: true,
        experiment: { milestone: '19.4' },
        description: 'Health verdict the most recent probe of the upstream stored. `UNKNOWN` before the ' \
          'first probe, and for a status this schema does not recognize.'

      field :last_health_checked_at, ::Types::TimeType, # rubocop:disable GraphQL/ExtractType -- flat shape mirrors the Artifact Registry settings contract
        null: true,
        experiment: { milestone: '19.4' },
        description: 'Timestamp of the most recent health probe of the upstream. Null until the first probe.'

      def last_health_status
        ::Types::ArtifactRegistry::HealthStatusEnum.recognized_or_unknown(object['last_health_status'])
      end

      def last_health_checked_at
        parse_time(object['last_health_checked_at'])
      end
    end
  end
end
