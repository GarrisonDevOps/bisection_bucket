# frozen_string_literal: true

module Types
  module PermissionTypes
    module ArtifactRegistry
      # rubocop: disable Graphql/AuthorizeTypes -- inherited from Base's
      # `authorize :read_artifact_registry`; the cop reads only this class body
      class Namespace < Base
        graphql_name 'ArtifactRegistryNamespacePermissions'
        description 'Per-action permissions Artifact Registry reports for the current user on a namespace.'

        DESCRIPTIONS = {
          'read_repository' => 'Indicates the user can read repositories of the namespace and their metadata.',
          'create_repository' => 'Indicates the user can create a repository in the namespace.',
          'update_repository' => "Indicates the user can change the settings of the namespace's repositories.",
          'delete_repository' => 'Indicates the user can delete repositories of the namespace.',
          'create_repository_upstream' => "Indicates the user can add an upstream to the namespace's repositories.",
          'update_repository_upstream' => "Indicates the user can change an upstream of the namespace's repositories.",
          'delete_repository_upstream' => "Indicates the user can remove an upstream from the namespace's repositories."
        }.freeze

        ::ArtifactRegistry::Permissions::Verdicts::NAMESPACE_ACTIONS.each do |action|
          verdict_field action,
            experiment: { milestone: '19.5' },
            description: DESCRIPTIONS.fetch(action)
        end
      end
      # rubocop: enable Graphql/AuthorizeTypes
    end
  end
end
