# frozen_string_literal: true

module Organizations
  class ArtifactRegistryController < ApplicationController
    include ArtifactRegistryGating

    feature_category :artifact_registry

    before_action :handle_activation_state

    # The setup page mount, reached only for an org with no mapping row; every
    # other outcome is answered by the before_action.
    def index; end

    private

    def handle_activation_state
      mapping = organization.artifact_registry_namespace_mapping

      # No row: only an owner may claim a slug, so the setup mount needs the update
      # ability on top of the read ability the gating concern already checked.
      return authorize_admin_organization! unless mapping

      registry = mapping.registry

      # One dependency being unreachable is not the instance being down, so the outage is
      # reported on an Artifact Registry page inside the organization rather than by the
      # instance-wide 503 page, which reads as the whole of GitLab being unavailable.
      return render :unavailable if registry.is_a?(::ArtifactRegistry::NamespaceMapping::ResolutionFailure)

      # A slug-less registry is a namespace that is permanently absent (an Artifact
      # Registry 404), so it answers not-found like any other missing resource, which is
      # what the repositories route already does with it.
      return render_404 if registry.slug.blank?

      # Non-read-serving statuses (for example disabled) redirect too and are
      # surfaced by the repositories app for now; a dedicated state is
      # https://gitlab.com/gitlab-org/gitlab/-/issues/623320.
      redirect_to_repositories(registry.slug)
    end

    def redirect_to_repositories(slug)
      redirect_to artifact_registry_repositories_organization_path(organization, slug)
    end
  end
end
