# frozen_string_literal: true

module ArtifactRegistry
  # A manifest addressed by its own digest. Subclasses `Manifest` for the base fields the list also
  # carries and keeps the detail-only arrays here, so a list row stays narrow while the two share
  # one runtime type.
  class ManifestDetail < Manifest
    expose_attribute :parents_count

    def tags
      string_list('tags')
    end

    # Each entry is a Hash carrying the child digest plus its platform triple.
    # A non-Hash entry is dropped so a malformed row can't slip through as another shape.
    def children
      hash_list('children')
    end

    def parent_digests
      string_list('parent_digests')
    end

    # nil (no annotations key on push) and empty Hash (empty map on push) mean
    # different things and are kept apart, not normalized into each other.
    # A non-Hash coerces to nil.
    def annotations
      map = @attributes['annotations']

      map if map.is_a?(Hash)
    end
  end
end
