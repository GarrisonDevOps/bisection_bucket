# frozen_string_literal: true

module Types
  module ArtifactRegistry
    class UpstreamRepositoryAssociationType < BaseObject
      graphql_name 'ArtifactRegistryUpstreamRepositoryAssociation'
      description 'One upstream of a virtual Artifact Registry repository: its position and a summary ' \
        'of the repository it points at.'

      authorize :read_artifact_registry

      include ::ArtifactRegistry::ExposesElementId

      exposes_element_id noun: 'upstream association', milestone: '19.5'

      authorize_granular_token skip_reason: :parent_authorizes

      field :position, GraphQL::Types::Int,
        null: false,
        experiment: { milestone: '19.5' },
        description: '1-based resolution position of the upstream, consulted in ascending order.'

      field :upstream_repository, ::Types::ArtifactRegistry::UpstreamRepositorySummaryType,
        null: false,
        experiment: { milestone: '19.5' },
        description: 'Summary of the repository the association points at.'
    end
  end
end
