# frozen_string_literal: true

module EE
  module PreferencesHelper
    extend ::Gitlab::Utils::Override
    include ::Gitlab::Utils::StrongMemoize

    override :excluded_dashboard_choices

    def excluded_dashboard_choices
      return [] if can?(current_user, :read_operations_dashboard)

      super
    end

    override :extensions_marketplace_view

    def extensions_marketplace_view
      if License.feature_available?(:remote_development) &&
          ::WebIde::ExtensionMarketplace.feature_enabled_from_application_settings?
        build_extensions_marketplace_view(
          title: s_("Preferences|Web IDE and Workspaces"),
          message: s_("PreferencesIntegrations|Uses %{extensions_marketplace_home} as the extension marketplace " \
            "for the Web IDE and Workspaces.")
        )
      elsif License.feature_available?(:remote_development)
        build_extensions_marketplace_view(
          title: s_("Preferences|Workspaces"),
          message: s_("PreferencesIntegrations|Uses %{extensions_marketplace_home} as the extension marketplace " \
            "for Workspaces.")
        )
      else
        super
      end
    end

    def group_view_choices
      strong_memoize(:group_view_choices) do
        choices = []
        choices << [_('Details (default)'), :details]
        choices << [_('Security dashboard'), :security_dashboard] if group_view_security_dashboard_enabled?
        choices
      end
    end

    def group_overview_content_preference?
      group_view_choices.size > 1
    end

    def should_show_code_suggestions_preferences?(user)
      ::Feature.enabled?(:enable_hamilton_in_user_preferences, user)
    end

    def duo_default_group_preference?
      can?(current_user, :assign_default_duo_group)
    end

    def orbit_preference?
      ::Ai::Orbit::Settings.orbit_in_duo_on?(current_user)
    end
    strong_memoize_attr :orbit_preference?

    def orbit_billable_namespace_candidates
      return [] unless can?(current_user, :update_governing_knowledge_graph_namespace)

      candidates = ::Analytics::KnowledgeGraph::GoverningNamespaceFinder.for(current_user).candidates.to_a
      # A single candidate is used as the fallback, so there is nothing to choose.
      candidates.size > 1 ? candidates : []
    end
    strong_memoize_attr :orbit_billable_namespace_candidates

    def orbit_billable_namespace_preference?
      orbit_billable_namespace_candidates.any?
    end

    private

    override :duo_preferences_tab
    def duo_preferences_tab
      return unless duo_preferences_available?

      { id: 'ai-assistance', title: s_('Preferences|AI assistance'), partial: 'duo' }
    end

    def duo_preferences_available?
      duo_default_group_preference? ||
        orbit_preference? ||
        orbit_billable_namespace_preference? ||
        should_show_code_suggestions_preferences?(current_user)
    end

    def group_view_security_dashboard_enabled?
      License.feature_available?(:security_dashboard)
    end
  end
end
