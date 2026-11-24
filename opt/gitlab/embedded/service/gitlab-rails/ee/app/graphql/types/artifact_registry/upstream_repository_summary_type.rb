# frozen_string_literal: true

module Types
  module ArtifactRegistry
    class UpstreamRepositorySummaryType < BaseObject
      graphql_name 'ArtifactRegistryUpstreamRepositorySummary'
      description 'Summary of a repository that is an upstream of a virtual Artifact Registry repository.'

      authorize :read_artifact_registry

      include ::ArtifactRegistry::ExposesElementId

      # Derived from the enum so a kind added there cannot start raising here as unsupported.
      CONTRACT_KINDS = ::Types::ArtifactRegistry::UpstreamRepositoryKindEnum
        .values.values.map(&:value).freeze

      CONTRACT_VISIBILITIES = ::Types::ArtifactRegistry::RepositoryVisibilityEnum
        .values.values.map(&:value).freeze

      exposes_element_id noun: 'upstream repository', milestone: '19.5'

      authorize_granular_token skip_reason: :parent_authorizes

      field :name, GraphQL::Types::String,
        null: false,
        experiment: { milestone: '19.5' },
        description: 'Name of the upstream repository.'

      field :format, ::Types::ArtifactRegistry::RepositoryFormatEnum,
        null: false,
        experiment: { milestone: '19.5' },
        description: 'Package format the upstream repository holds.'

      field :kind, ::Types::ArtifactRegistry::UpstreamRepositoryKindEnum,
        null: true,
        experiment: { milestone: '19.5' },
        description: 'How the upstream repository sources its artifacts. ' \
          'Artifact Registry returns `hosted` or `remote` by contract; a value outside those ' \
          'resolves `null` alongside a top-level error rather than a badge.'

      field :user_permissions, ::Types::PermissionTypes::ArtifactRegistry::Repository,
        null: false,
        experiment: { milestone: '19.5' },
        description: 'Permissions Artifact Registry grants the current user on the upstream repository. ' \
          'Advisory, because Artifact Registry authorizes every request on its own. ' \
          'Every permission is `false` when Artifact Registry returned no verdicts. ' \
          '`upstreamRepositories` returns `null` when the `artifact_registry_ui` feature flag is ' \
          'disabled, so this block is not reached.'

      field :visibility, ::Types::ArtifactRegistry::RepositoryVisibilityEnum,
        null: true,
        experiment: { milestone: '19.5' },
        description: 'Who can read the upstream repository. Null when the current user cannot read the ' \
          'upstream repository. A value outside this enum resolves `null` alongside a top-level error.'

      field :size_bytes, GraphQL::Types::BigInt,
        null: true,
        experiment: { milestone: '19.5' },
        description: 'Storage the upstream repository occupies, in bytes. Buffered, so it can lag. ' \
          'Null when the current user cannot read the upstream repository.'

      field :settings, ::Types::ArtifactRegistry::UpstreamRepositorySummarySettingsType,
        null: true,
        experiment: { milestone: '19.5' },
        description: 'Upstream configuration of a remote upstream repository. Null on a hosted upstream, ' \
          'and when the current user cannot read the upstream repository.'

      def kind
        raw = object.kind
        return raw if CONTRACT_KINDS.include?(raw)

        # `kind` is required by contract, so a missing one is as much a breach as an unknown one.
        raise ::Gitlab::Graphql::Errors::BaseError,
          "Artifact Registry returned an unsupported upstream kind: #{raw.presence || 'none'}."
      end

      def visibility
        raw = object.visibility
        return raw if raw.nil? || CONTRACT_VISIBILITIES.include?(raw)

        raise ::Gitlab::Graphql::Errors::BaseError,
          "Artifact Registry returned an unsupported upstream visibility: #{raw}."
      end

      def user_permissions
        ::Types::PermissionTypes::ArtifactRegistry::Base::Block.new(
          verdicts: object.permissions, declaring_type: self.class.graphql_name
        )
      end
    end
  end
end
