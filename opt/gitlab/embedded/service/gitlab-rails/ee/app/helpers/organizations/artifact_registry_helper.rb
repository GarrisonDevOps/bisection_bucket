# frozen_string_literal: true

module Organizations
  module ArtifactRegistryHelper
    def artifact_registry_repositories_app_data(organization, slug)
      {
        organization_gid: organization.to_global_id,
        slug: slug,
        base_path: artifact_registry_repositories_organization_path(organization, slug),
        client_base_url: artifact_registry_client_base_url,
        organization_access_path: readable_organization_access_path(organization)
      }.to_json
    end

    def artifact_registry_setup_app_data(organization)
      {
        organization_path: organization.path,
        client_base_url: artifact_registry_client_base_url
      }.to_json
    end

    private

    # Nil unless ArtifactRegistry::Configuration.configured?, which is the same predicate the
    # Artifact Registry routes gate on, so a view that renders always carries an origin rather
    # than composing a package-manager URL from a value the gate refused.
    def artifact_registry_client_base_url
      ::ArtifactRegistry::Configuration.client_base_url
    end

    # TODO: Mirrors the Organizations::AccessController gate and ManageMenu#show_organization_access_menu_item?.
    # Move them onto one ability when Artifact Admins can open Organization access:
    # https://gitlab.com/gitlab-org/gitlab/-/work_items/629716
    def readable_organization_access_path(organization)
      return unless ::Feature.enabled?(:organization_access_ui, current_user)
      return unless can?(current_user, :read_organization_user, organization)

      artifact_registry_access_organization_path(organization)
    end
  end
end
