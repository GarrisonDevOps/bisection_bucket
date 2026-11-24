# frozen_string_literal: true

module Types
  module ArtifactRegistry
    class UpstreamRepositoryKindEnum < BaseEnum
      graphql_name 'ArtifactRegistryUpstreamRepositoryKind'
      description 'How an upstream of a virtual Artifact Registry repository sources its artifacts. ' \
        'An upstream is never virtual.'

      value 'HOSTED', value: 'hosted', description: 'Stores artifacts published to GitLab.'
      value 'REMOTE', value: 'remote', description: 'Proxies and caches an upstream registry.'
    end
  end
end
