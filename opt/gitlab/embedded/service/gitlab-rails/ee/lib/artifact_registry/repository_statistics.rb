# frozen_string_literal: true

module ArtifactRegistry
  class RepositoryStatistics < ValueObject
    expose_attribute :packages_count, :images_count
  end
end
