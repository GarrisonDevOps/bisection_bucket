# frozen_string_literal: true

module ProjectLinksHelper
  def custom_role_for_project_link_enabled?(project)
    return false unless project
    return false unless project.root_ancestor.custom_roles_enabled?

    if ::Gitlab::Saas.feature_available?(:gitlab_com_subscriptions)
      ::Feature.enabled?(:assign_custom_roles_to_project_links_saas, project.root_ancestor)
    else
      ::License.feature_available?(:custom_roles)
    end
  end
end
