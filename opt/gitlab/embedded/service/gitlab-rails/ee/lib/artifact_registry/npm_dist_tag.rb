# frozen_string_literal: true

module ArtifactRegistry
  # `version` is a denormalized version string (e.g. '1.10.0'), not an ArtifactRegistry::Version
  # and distinct from `version_id`; the tag is mutable, so both track whatever version it now names.
  class NpmDistTag < ValueObject
    expose_attribute :id, :name, :version_id, :version
  end
end
