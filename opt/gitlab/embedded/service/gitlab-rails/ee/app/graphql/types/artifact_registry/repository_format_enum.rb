# frozen_string_literal: true

module Types
  module ArtifactRegistry
    class RepositoryFormatEnum < BaseEnum
      graphql_name 'ArtifactRegistryRepositoryFormat'
      description 'Package format an Artifact Registry repository holds.'

      value 'DOCKER', value: 'docker', description: 'Docker images.'
      value 'OCI', value: 'oci', description: 'OCI artifacts.'
      value 'MAVEN', value: 'maven', description: 'Maven packages.'
      value 'NPM', value: 'npm', description: 'npm packages.'
    end
  end
end
