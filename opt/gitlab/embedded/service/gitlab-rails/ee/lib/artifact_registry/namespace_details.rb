# frozen_string_literal: true

module ArtifactRegistry
  # `permissions` is nil when not requested, an absent `Verdicts` when requested
  # but not served, or populated when served.
  class NamespaceDetails < ValueObject
    include TimeCoercion

    attr_reader :permissions

    expose_attribute :slug

    def initialize(attributes = {}, permissions = nil)
      super(attributes)
      @permissions = permissions
    end

    def created_at
      parse_time(@attributes['created_at'])
    end
  end
end
