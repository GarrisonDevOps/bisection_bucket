# frozen_string_literal: true

module Types
  module ArtifactRegistry
    class RepositoryKindEnum < BaseEnum
      graphql_name 'ArtifactRegistryRepositoryKind'
      description 'How an Artifact Registry repository sources its artifacts.'

      value 'HOSTED', value: 'hosted', description: 'Stores artifacts published to GitLab.'
      value 'VIRTUAL', value: 'virtual', description: 'Serves other repositories through a single endpoint.'
      value 'REMOTE', value: 'remote', description: 'Proxies and caches an upstream registry.'
    end
  end
end
