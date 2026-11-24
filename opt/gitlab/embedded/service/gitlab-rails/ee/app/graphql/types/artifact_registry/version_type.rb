# frozen_string_literal: true

module Types
  module ArtifactRegistry
    class VersionType < BaseObject
      graphql_name 'ArtifactRegistryVersion'
      description 'Version of a package in an Artifact Registry repository (Maven and npm).'

      # Never evaluated: the repository field's `skip_type_authorization` empties this first, and a
      # bare version (no presenter) has no policy, so dropping the skip would raise rather than
      # authorize. Declared so the type still states what authorizes it.
      authorize :read_artifact_registry

      include ::ArtifactRegistry::ExposesElementId

      # Anchored so a partial hex string cannot match. AR stores the SHA as an opaque value, so
      # the commit-field guard pairs this with an is_a?(String) check.
      COMMIT_ROUTE_SHA = /\A#{::Gitlab::Git::Commit::RAW_SHA_PATTERN}\z/

      # Unioned into one batch key so `project` and the commit fields coalesce into one query per
      # project: `namespace: [:route]` feeds the path route, `project_feature` the read_code gate.
      PROJECT_PRELOADS = [:project_feature, { namespace: [:route] }].freeze

      exposes_element_id noun: 'version', milestone: '19.4'

      # A version owns no group or project to scope a token against.
      authorize_granular_token skip_reason: :parent_authorizes

      field :version, GraphQL::Types::String,
        null: false,
        experiment: { milestone: '19.4' },
        description: 'Version string of the package.'

      field :dist_tags, [GraphQL::Types::String],
        null: false,
        experiment: { milestone: '19.4' },
        description: 'Names of the npm dist-tags bound to the version, in ascending name order. ' \
          'Empty for Maven versions.'

      field :created_at, ::Types::TimeType,
        null: true,
        experiment: { milestone: '19.4' },
        description: 'Timestamp the version was published. Null when Artifact Registry stored none.'

      field :size_bytes, GraphQL::Types::BigInt,
        null: true,
        method: :size,
        experiment: { milestone: '19.4' },
        description: 'Stored size of the version in bytes. Null for a Maven version until ' \
          'Artifact Registry serializes the column, and on a remote repository.'

      # rubocop:disable GraphQL/ExtractType -- the created_ group (created_at, created_by) is a timestamp and a user, not a sub-object to extract
      field :created_by, ::Types::UserType,
        null: true,
        experiment: { milestone: '19.4' },
        description: 'User who published the version, resolved from the reference Artifact ' \
          'Registry stores. Null when it stored none or the user no longer exists.'

      field :project, ::Types::ProjectType,
        null: true,
        experiment: { milestone: '19.4' },
        description: 'Project the version was published from, resolved from the reference ' \
          'Artifact Registry stores. Null when it stored none, the project no longer exists, ' \
          'or the viewer cannot see the project.'
      # rubocop:enable GraphQL/ExtractType

      # rubocop:disable GraphQL/ExtractType -- the commit_ group (commit_sha, commit_path) has no commit object to extract; AR stores only the opaque SHA
      field :commit_sha, GraphQL::Types::String,
        null: true,
        experiment: { milestone: '19.4' },
        description: 'Commit SHA the version was published from, within the resolved project. ' \
          'Null when there is no SHA or project, or the viewer cannot read the project code.'

      field :commit_path, GraphQL::Types::String,
        null: true,
        experiment: { milestone: '19.4' },
        description: 'Web path to the publishing commit within the resolved project. Null ' \
          'when there is no SHA or project, or the viewer cannot read the project code.'
      # rubocop:enable GraphQL/ExtractType

      def created_by
        return unless object.created_by

        ::Gitlab::Graphql::Loaders::BatchModelLoader.new(::User, object.created_by).find
      end

      def project
        return unless object.project_id

        ::Gitlab::Graphql::Loaders::BatchModelLoader.new(::Project, object.project_id, PROJECT_PRELOADS).find
      end

      # Each commit field leaks a repository identifier, so both are null unless the viewer can
      # read the project code, not merely see the project.
      def commit_sha
        ::Gitlab::Graphql::Lazy.with_value(authorized_commit_project) do |commit_project|
          object.git_commit_sha if commit_project
        end
      end

      def commit_path
        ::Gitlab::Graphql::Lazy.with_value(authorized_commit_project) do |commit_project|
          ::Gitlab::Routing.url_helpers.project_commit_path(commit_project, object.git_commit_sha) if commit_project
        end
      end

      private

      # Lazily resolves to the project when the viewer can read its code, else nil. The SHA guard
      # rejects a non-string or out-of-range value before it reaches the commit route.
      def authorized_commit_project
        sha = object.git_commit_sha
        return unless sha.is_a?(String) && sha.match?(COMMIT_ROUTE_SHA) && object.project_id

        ::Gitlab::Graphql::Lazy.with_value(project) do |commit_project|
          next unless commit_project && ::Types::ProjectType.authorized?(commit_project, context)
          next unless ::Ability.allowed?(current_user, :read_code, commit_project)

          commit_project
        end
      end
    end
  end
end
