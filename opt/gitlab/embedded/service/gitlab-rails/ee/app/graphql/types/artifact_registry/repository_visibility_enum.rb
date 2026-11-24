# frozen_string_literal: true

module Types
  module ArtifactRegistry
    # Decodes every visibility Artifact Registry can return rather than the narrower set the
    # current rollout creates: a returnable value missing here fails coercion for the whole page.
    class RepositoryVisibilityEnum < BaseEnum
      graphql_name 'ArtifactRegistryRepositoryVisibility'
      description 'Who can read an Artifact Registry repository.'

      value 'PRIVATE', value: 'private', description: 'Readable only by users holding an Artifact Registry role.'
      value 'INTERNAL', value: 'internal', description: 'Readable by any authenticated user.'
      value 'PUBLIC', value: 'public', description: 'Readable by anyone.'
    end
  end
end
