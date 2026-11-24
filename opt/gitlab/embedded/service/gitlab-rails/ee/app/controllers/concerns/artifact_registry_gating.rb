# frozen_string_literal: true

# Shared gating for the organization Artifact Registry controllers. An unconfigured base URL,
# a missing feature, and a forbidden organization are indistinguishable: all 404.
module ArtifactRegistryGating
  extend ActiveSupport::Concern

  included do
    before_action :ensure_artifact_registry_available!
  end

  private

  def ensure_artifact_registry_available!
    return if ::ArtifactRegistry::Configuration.configured? &&
      Feature.enabled?(:artifact_registry_ui, organization) &&
      can?(current_user, :read_artifact_registry, organization)

    render_404
  end
end
