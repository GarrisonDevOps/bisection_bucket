# frozen_string_literal: true

module EE
  module GroupsFinder
    include Gitlab::Auth::Saml::SsoSessionFilterable
    extend ::Gitlab::Utils::Override

    private

    override :filter_groups
    def filter_groups(groups)
      groups = top_level_knowledge_graph_enabled_groups || groups
      groups = super(groups)
      groups = by_saml_sso_session(groups)
      groups = by_repository_storage(groups)
      groups = by_knowledge_graph_enabled(groups)
      by_duo_agent_platform_enabled(groups)
    end

    def by_saml_sso_session(groups)
      filter_by_saml_sso_session(groups, :filter_expired_saml_session_groups)
    end

    def by_repository_storage(groups)
      return groups if params[:repository_storage].blank?

      groups.by_repository_storage(params[:repository_storage])
    end

    def by_knowledge_graph_enabled(groups)
      return groups unless params[:with_knowledge_graph_enabled]
      return groups if top_level_knowledge_graph_enabled_filter?

      groups.with_knowledge_graph_enabled_namespace
    end

    def by_duo_agent_platform_enabled(groups)
      return groups unless params[:with_duo_agent_platform_enabled]
      return groups.with_duo_agent_platform_enabled if ::Gitlab::Saas.feature_available?(:gitlab_com_subscriptions)

      ::Ai::DuoWorkflow.duo_agent_platform_available? ? groups : groups.none
    end

    def top_level_knowledge_graph_enabled_groups
      return unless top_level_knowledge_graph_enabled_filter?

      ::Group.id_in(::Analytics::Orbit::MemberGroups.for(current_user).on_root_ids)
    end

    def top_level_knowledge_graph_enabled_filter?
      current_user &&
        params[:with_knowledge_graph_enabled] &&
        params[:top_level_only].present? &&
        !all_available? &&
        params[:owned].blank? &&
        params[:parent].blank? &&
        !min_access_level? &&
        params.fetch(:include_ancestors, true)
    end
  end
end
