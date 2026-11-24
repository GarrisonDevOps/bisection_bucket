# frozen_string_literal: true

module Types
  module PermissionTypes
    module ArtifactRegistry
      # rubocop: disable Graphql/AuthorizeTypes -- inherited from Base's
      # `authorize :read_artifact_registry`; the cop reads only this class body
      class Repository < Base
        graphql_name 'ArtifactRegistryRepositoryPermissions'
        description 'Per-action permissions Artifact Registry reports for the current user on a repository.'

        DESCRIPTIONS = {
          'read_repository' => 'Indicates the user can read the repository and its metadata.',
          'update_repository' => "Indicates the user can change the repository's settings.",
          'delete_repository' => 'Indicates the user can delete the repository.',
          'create_repository_upstream' => 'Indicates the user can add an upstream to the repository.',
          'update_repository_upstream' => 'Indicates the user can change an upstream of the repository.',
          'delete_repository_upstream' => 'Indicates the user can remove an upstream from the repository.',
          'read_artifact' => 'Indicates the user can read artifacts held by the repository.',
          'create_artifact' => 'Indicates the user can publish artifacts to the repository.',
          'delete_artifact' => 'Indicates the user can delete artifacts from the repository.',
          'read_role_assignment' => 'Indicates the user can view who holds a role on the repository.',
          'create_role_assignment' => 'Indicates the user can grant a role on the repository.',
          'update_role_assignment' => "Indicates the user can change a member's role on the repository.",
          'delete_role_assignment' => 'Indicates the user can revoke a role on the repository.'
        }.freeze

        MILESTONES = {
          'read_repository' => '19.5',
          'update_repository' => '19.5',
          'delete_repository' => '19.5',
          'create_repository_upstream' => '19.5',
          'update_repository_upstream' => '19.5',
          'delete_repository_upstream' => '19.5',
          'read_artifact' => '19.5',
          'create_artifact' => '19.5',
          'delete_artifact' => '19.5',
          'read_role_assignment' => '19.6',
          'create_role_assignment' => '19.6',
          'update_role_assignment' => '19.6',
          'delete_role_assignment' => '19.6'
        }.freeze

        ::ArtifactRegistry::Permissions::Verdicts::REPOSITORY_ACTIONS.each do |action|
          verdict_field action,
            experiment: { milestone: MILESTONES.fetch(action) },
            description: DESCRIPTIONS.fetch(action)
        end
      end
      # rubocop: enable Graphql/AuthorizeTypes
    end
  end
end
