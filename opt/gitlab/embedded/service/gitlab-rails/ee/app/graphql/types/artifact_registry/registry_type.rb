# frozen_string_literal: true

module Types
  module ArtifactRegistry
    class RegistryType < BaseObject
      # The flat schema namespace would otherwise derive `Registry`, which is too generic.
      graphql_name 'ArtifactRegistry'
      description 'Artifact Registry an organization is activated for.'

      authorize :read_artifact_registry

      # Reachable only through the organization field, which authorizes against the organization.
      authorize_granular_token skip_reason: :parent_authorizes

      # Artifact Registry's own UUID, not a GitLab global ID: BaseObject#id would try to
      # encode one for a value object that has none. `hash_key:` reads the member off the
      # Registry struct, which graphql-ruby resolves before it would reach BaseObject#id.
      field :id, GraphQL::Types::ID,
        null: false,
        hash_key: :ar_namespace_id,
        experiment: { milestone: '19.5' },
        description: "Artifact Registry's UUID for the namespace mapped to the organization. " \
          'Neither a GitLab namespace nor a GitLab global ID. Pass it as `resourceId` to ' \
          'the Artifact Registry role mutations. Present even when the status is `unknown`.'

      field :slug, GraphQL::Types::String,
        null: true,
        experiment: { milestone: '19.4' },
        description: "Registry slug, Artifact Registry's immutable identifier for the namespace. " \
          '`null` when the status is `unknown`.'

      field :status, GraphQL::Types::String,
        null: false,
        experiment: { milestone: '19.4' },
        description: 'Status Artifact Registry returned, one of `active`, `suspended`, ' \
          '`disabled`, `blocked`, `deleted`, or `purged`, or `unknown` when the mapped ' \
          'namespace did not resolve. Deliberately a string rather than an enum so a ' \
          'status Artifact Registry adds within its API version reaches the response ' \
          'instead of raising.'

      field :created_at, ::Types::TimeType,
        null: true,
        experiment: { milestone: '19.4' },
        description: 'Timestamp the registry was provisioned, presented as the active-since ' \
          'date. `null` when the status is `unknown`.'

      field :user_permissions, ::Types::PermissionTypes::ArtifactRegistry::Namespace,
        null: false,
        experiment: { milestone: '19.5' },
        description: 'Permissions Artifact Registry grants the current user on the namespace, read ' \
          'from the namespace details as the user when this field is selected. Advisory, because ' \
          'Artifact Registry authorizes every request on its own. Every permission is `false` when ' \
          'Artifact Registry returned no verdicts. The parent field returns `null` when the ' \
          '`artifact_registry_ui` feature flag is disabled, so this block is not reached.',
        resolver: ::Resolvers::ArtifactRegistry::NamespacePermissionsResolver

      field :statistics, ::Types::ArtifactRegistry::NamespaceStatisticsType,
        null: true,
        experiment: { milestone: '19.5' },
        description: 'Namespace-wide Artifact Registry statistics, read as the current user when ' \
          'this field is selected. `null` on any unresolved read, so an unavailable service or a ' \
          'drifted slug omits the figures rather than raising. The parent field returns `null` ' \
          'when the `artifact_registry_ui` feature flag is disabled, so this field is not reached.',
        resolver: ::Resolvers::ArtifactRegistry::NamespaceStatisticsResolver
    end
  end
end
