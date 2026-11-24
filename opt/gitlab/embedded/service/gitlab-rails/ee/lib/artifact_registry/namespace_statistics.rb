# frozen_string_literal: true

module ArtifactRegistry
  class NamespaceStatistics < ValueObject
    expose_attribute :repositories_count, :deduplicated_size_bytes
  end
end
