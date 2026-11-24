# frozen_string_literal: true

module ArtifactRegistry
  # Shared reads for the Artifact Registry fields that hang off the repository detail type:
  # the single-artifact fields and the packages, images, versions, and manifests connections.
  module ResolvesOnRepository
    extend ActiveSupport::Concern

    private

    # `Resolvers::BaseResolver#object` unwraps the presenter to its bare value object, dropping
    # the organization; reads go through `@object` so the slug and memoized client stay reachable.
    def presented_repository
      @object
    end

    def artifact_registry_organization
      presented_repository.organization
    end

    # Each element carries the repository it was read through, so a child connection mounted on
    # the element type reaches the slug and the memoized client.
    def wrap_in_artifact_presenter(element)
      ::ArtifactRegistry::ArtifactPresenter.new(element, repository: presented_repository)
    end
  end
end
