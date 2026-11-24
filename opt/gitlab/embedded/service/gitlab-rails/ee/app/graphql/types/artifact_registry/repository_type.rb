# frozen_string_literal: true

module Types
  module ArtifactRegistry
    class RepositoryType < BaseObject
      graphql_name 'ArtifactRegistryRepository'
      description 'Repository in Artifact Registry.'

      connection_type_class ::Types::ArtifactRegistry::RepositoryConnectionType

      authorize :read_artifact_registry

      include ::ArtifactRegistry::ExposesElementId

      exposes_element_id noun: 'repository', milestone: '19.5'

      # A repository is only reachable through the organization connection field, which authorizes
      # against the organization, and it owns no group or project to scope a token against.
      authorize_granular_token skip_reason: :parent_authorizes

      field :name, GraphQL::Types::String,
        null: false,
        experiment: { milestone: '19.3' },
        description: 'Name of the repository, unique within its namespace.'

      field :format, ::Types::ArtifactRegistry::RepositoryFormatEnum,
        null: false,
        experiment: { milestone: '19.3' },
        description: 'Package format the repository holds.'

      field :kind, ::Types::ArtifactRegistry::RepositoryKindEnum,
        null: false,
        experiment: { milestone: '19.3' },
        description: 'How the repository sources its artifacts.'

      field :visibility, ::Types::ArtifactRegistry::RepositoryVisibilityEnum,
        null: false,
        experiment: { milestone: '19.3' },
        description: 'Who can read the repository.'

      field :artifacts_count, GraphQL::Types::BigInt,
        null: false,
        experiment: { milestone: '19.4' },
        description: 'Number of artifacts the repository holds. Buffered, so it can lag.'

      field :downloads_count, GraphQL::Types::BigInt,
        null: false,
        experiment: { milestone: '19.3' },
        description: 'Number of artifact downloads from the repository. Buffered, so it can lag.'

      field :size_bytes, GraphQL::Types::BigInt,
        null: false,
        experiment: { milestone: '19.3' },
        description: 'Storage the repository occupies, in bytes. Buffered, so it can lag.'

      field :created_at, ::Types::TimeType,
        null: true,
        experiment: { milestone: '19.4' },
        description: 'Timestamp of when the repository was created. Null when the time is unknown.'

      field :created_by, ::Types::UserType, # rubocop:disable GraphQL/ExtractType -- flat shape mirrors the Artifact Registry repository contract
        null: true,
        experiment: { milestone: '19.4' },
        description: 'User who created the repository. Null when the creator is unknown or no longer exists.'

      field :updated_by, ::Types::UserType,
        null: true,
        experiment: { milestone: '19.4' },
        description: 'User who last changed the repository. Null when the editor is unknown or no longer exists.'

      field :last_updated_at, ::Types::TimeType,
        null: true,
        experiment: { milestone: '19.3' },
        description: 'Time the repository content last changed. Null when the content never changed.'

      field :description, GraphQL::Types::String,
        null: true,
        experiment: { milestone: '19.3' },
        description: 'Human-readable description of the repository. Null when unset.'

      field :settings, ::Types::ArtifactRegistry::RemoteSettingsType,
        null: true,
        experiment: { milestone: '19.3' },
        description: 'Upstream configuration Artifact Registry returned for the repository. Null when ' \
          'it returned none, so null on a hosted or virtual repository.'

      field :user_permissions, ::Types::PermissionTypes::ArtifactRegistry::Repository,
        null: false,
        experiment: { milestone: '19.5' },
        description: 'Permissions Artifact Registry grants the current user on the repository. ' \
          'Advisory, because Artifact Registry authorizes every request on its own. ' \
          'Every permission is `false` when Artifact Registry returned no verdicts. ' \
          'The parent field returns `null` when the `artifact_registry_ui` feature flag is ' \
          'disabled, so this block is not reached.'

      # The Artifact Registry ids are opaque GitLab user ids. UserType runs its own
      # authorization, so the batched load resolves null for a missing user rather than
      # this type re-checking read_user.
      def created_by
        load_user(object.created_by)
      end

      def updated_by
        load_user(object.updated_by)
      end

      def settings
        object.settings.presence
      end

      def user_permissions
        ::Types::PermissionTypes::ArtifactRegistry::Base::Block.new(
          verdicts: object.permissions, declaring_type: self.class.graphql_name
        )
      end

      private

      def load_user(id)
        return if id.blank?

        ::Gitlab::Graphql::Loaders::BatchModelLoader.new(::User, id).find
      end
    end
  end
end
