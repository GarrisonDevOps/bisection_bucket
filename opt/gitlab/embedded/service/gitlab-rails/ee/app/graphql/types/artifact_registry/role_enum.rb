# frozen_string_literal: true

module Types
  module ArtifactRegistry
    class RoleEnum < BaseEnum
      graphql_name 'ArtifactRegistryRole'
      description 'Artifact Registry role that can be assigned to a user.'

      value 'ARTIFACT_VIEWER', value: :artifact_viewer,
        description: 'Consume artifacts and browse the registry.'
      value 'ARTIFACT_CONTRIBUTOR', value: :artifact_contributor,
        description: 'Publish artifacts in addition to consuming them.'
      value 'ARTIFACT_MANAGER', value: :artifact_manager,
        description: 'Manage artifacts and repository configuration.'
      value 'ARTIFACT_ADMIN', value: :artifact_admin,
        description: 'Administer registry-wide configuration and access.'
    end
  end
end
