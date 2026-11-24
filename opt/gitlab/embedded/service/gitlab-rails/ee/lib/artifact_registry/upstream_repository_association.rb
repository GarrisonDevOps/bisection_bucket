# frozen_string_literal: true

module ArtifactRegistry
  class UpstreamRepositoryAssociation < ValueObject
    expose_attribute :id, :position

    def initialize(attributes = {}, upstream_permissions = nil)
      super(attributes)
      @upstream_permissions = upstream_permissions
    end

    def upstream_repository
      summary = @attributes['upstream_repository']

      UpstreamRepositorySummary.new(summary.is_a?(Hash) ? summary : nil, @upstream_permissions)
    end
  end
end
