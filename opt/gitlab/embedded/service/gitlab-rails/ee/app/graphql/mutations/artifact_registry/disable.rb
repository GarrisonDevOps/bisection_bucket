# frozen_string_literal: true

module Mutations
  module ArtifactRegistry
    # Disables an organization's registry through Artifact Registry's disable
    # condition endpoint.
    class Disable < ConditionMutation
      graphql_name 'ArtifactRegistryDisable'
      description 'Disables Artifact Registry for the organization resolved from the ' \
        'request context (the X-GitLab-Organization-ID header, or the user default organization). ' \
        'Does not disable Artifact Registry if the `artifact_registry_ui` feature flag is disabled.'

      condition :disable_namespace
    end
  end
end
