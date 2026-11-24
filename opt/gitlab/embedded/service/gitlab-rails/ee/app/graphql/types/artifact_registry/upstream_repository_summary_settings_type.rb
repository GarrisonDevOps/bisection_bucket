# frozen_string_literal: true

module Types
  module ArtifactRegistry
    class UpstreamRepositorySummarySettingsType < BaseObject
      graphql_name 'ArtifactRegistryUpstreamRepositorySummarySettings'
      description 'Settings a remote upstream repository shows in the upstream list of a virtual ' \
        'Artifact Registry repository.'

      authorize :read_artifact_registry

      authorize_granular_token skip_reason: :parent_authorizes

      field :url, GraphQL::Types::String,
        null: true,
        experiment: { milestone: '19.5' },
        description: 'Base URL of the upstream registry, in the canonical form Artifact Registry stores.'

      field :last_health_status, ::Types::ArtifactRegistry::HealthStatusEnum,
        null: true,
        experiment: { milestone: '19.5' },
        description: 'Health verdict the most recent probe of the upstream stored. `UNKNOWN` before the ' \
          'first probe, and for a status this schema does not recognize.'

      def last_health_status
        ::Types::ArtifactRegistry::HealthStatusEnum.recognized_or_unknown(object['last_health_status'])
      end
    end
  end
end
