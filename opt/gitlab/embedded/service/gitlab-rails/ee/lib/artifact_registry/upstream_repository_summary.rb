# frozen_string_literal: true

module ArtifactRegistry
  class UpstreamRepositorySummary < ValueObject
    attr_reader :permissions

    expose_attribute :id, :name, :format, :kind, :visibility, :size_bytes

    def initialize(attributes = {}, permissions = nil)
      super(attributes)
      @permissions = permissions
    end

    def settings
      settings = @attributes['settings']

      settings.is_a?(Hash) ? settings.presence : nil
    end
  end
end
