# frozen_string_literal: true

module Organizations
  class ArtifactRegistryRepositoriesController < ApplicationController
    include ArtifactRegistryGating

    feature_category :artifact_registry

    before_action :ensure_trash_ui_enabled!, only: :trash
    before_action :ensure_resolved_slug!
    before_action only: :index do
      push_frontend_feature_flag(:artifact_registry_repository_role_management_ui, organization)
    end

    def index; end

    def trash; end

    private

    def ensure_trash_ui_enabled!
      render_404 unless Feature.enabled?(:artifact_registry_trash_ui, organization)
    end

    # A slug that does not match, and one the viewer may not see, both reach
    # render_404 by the same path, so the responses are byte-identical and cannot
    # enumerate an organization's slugs.
    #
    # A slug flip (rename, or delete-and-re-provision) stays a dead-end 404 with
    # no redirect: a redirect Location would leak the resolved slug to a probing
    # non-member. Slug discovery lands in #602638.
    def ensure_resolved_slug!
      registry = resolved_registry
      return render_404 if registry.nil?

      # A client failure cannot confirm the slug, so the app mounts on the one requested
      # and reports the outage itself. Every well-formed slug is answered identically,
      # so a mount the registry did not confirm still enumerates nothing.
      return ensure_well_formed_slug! if unreachable_registry?

      # An AR 404 resolves to a slug-less Registry: a permanently absent namespace, so
      # it answers 404 like any other missing resource.
      return render_404 if registry.slug.nil?

      render_404 unless requested_slug == registry.slug
    end

    def ensure_well_formed_slug!
      render_404 unless ::ArtifactRegistry::SlugValidator.new(requested_slug).valid?
    end

    def unreachable_registry?
      resolved_registry.is_a?(::ArtifactRegistry::NamespaceMapping::ResolutionFailure)
    end

    # One resolution per request, shared by the gate and the view's mount data;
    # memoizing drops redundant model-cache lookups. Nil when there is no mapping
    # row (strong_memoize_attr caches nil too).
    def resolved_registry
      organization.artifact_registry_namespace_mapping&.registry
    end
    strong_memoize_attr :resolved_registry

    def requested_slug
      params.permit(:slug)[:slug]
    end

    # The mount anchors on the resolved slug, not the request path, so a
    # catch-all sub-path serves the same app as the base route. An unreachable
    # registry has no resolved slug to anchor on, so the requested one stands in.
    def resolved_slug
      return requested_slug if unreachable_registry?

      resolved_registry.slug
    end
    helper_method :resolved_slug
  end
end
