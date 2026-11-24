# frozen_string_literal: true

module ArtifactRegistry
  module AcceptsUpstreamRepositoryIds
    extend ActiveSupport::Concern

    included do
      argument :upstream_repository_ids, [GraphQL::Types::ID],
        required: false,
        validates: { allow_null: false, length: { maximum: ::Types::BaseArgument::MAX_ARRAY_SIZE } },
        experiment: { milestone: '19.5' },
        description: 'Upstream repositories of a virtual repository, as Artifact Registry repository IDs in ' \
          'resolution order. On update, replaces the whole upstream list, and an empty list removes every ' \
          "upstream. Rejected on any other kind. Maximum is #{::Types::BaseArgument::MAX_ARRAY_SIZE} IDs per " \
          'request. Artifact Registry sets a lower limit on how many upstreams a repository can have.'

      field :refused_upstream_repository_id, GraphQL::Types::ID,
        null: true,
        experiment: { milestone: '19.5' },
        description: 'Artifact Registry ID of the first upstream list entry that Artifact Registry refused. ' \
          'Null unless an entry was refused.'
    end

    private

    def render_artifact_registry_api_error(error, *)
      super

      { refused_upstream_repository_id: error.details&.dig('upstream_repository_id') }
    end
  end
end
