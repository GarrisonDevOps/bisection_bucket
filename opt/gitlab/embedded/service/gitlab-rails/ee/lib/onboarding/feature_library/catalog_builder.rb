# frozen_string_literal: true

module Onboarding
  module FeatureLibrary
    # Assembles the feature catalog sent to the AI Gateway for feature search.
    class CatalogBuilder
      PANELS = {
        'project' => {
          panel_class: ::Sidebars::Projects::SuperSidebarPanel,
          context_class: ::Sidebars::Projects::Context
        },
        'group' => {
          panel_class: ::Sidebars::Groups::SuperSidebarPanel,
          context_class: ::Sidebars::Groups::Context
        }
      }.freeze

      def initialize(panel:, user:, resource:)
        @panel = panel
        @user = user
        @resource = resource
      end

      # @return [Array<Hash>] feature entries: { id:, name:, description:, tier: }
      def execute
        return [] unless PANELS.key?(panel)

        menu_items
          .select { |item| item[:description].present? }
          .map { |item| entry_for(item) }
          .uniq { |entry| entry[:id] }
      rescue StandardError => e
        Gitlab::ErrorTracking.track_exception(e)
        []
      end

      private

      attr_reader :panel, :user, :resource

      def menu_items
        config = PANELS.fetch(panel)
        sidebar_context = config[:context_class].new(**context_args)

        config[:panel_class].new(sidebar_context)
          .super_sidebar_menu_items
          .flat_map { |menu| Array(menu[:items]) }
      end

      # Menu classes read assorted context values that are normally computed by view
      # helpers. We are not in a request here, so we supply safe defaults: these only
      # gate a handful of promo/discovery items and do not affect the Feature Library
      # descriptions we collect.
      def context_args
        base = { current_user: user, container: resource, is_super_sidebar: true, show_promotions: false }
        panel == 'project' ? base.merge(project_context_args) : base.merge(group_context_args)
      end

      def project_context_args
        {
          current_ref: resource.default_branch,
          can_view_pipeline_editor: false,
          show_cluster_hint: false,
          show_discover_project_security: false,
          jira_issues_integration: jira_issues_integration?
        }
      end

      def group_context_args
        { show_discover_group_security: false }
      end

      # Mirrors EE::IntegrationsHelper#project_jira_issues_integration?. WorkItemsMenu/IssuesMenu
      # read `context.jira_issues_integration` whenever the project's external issue tracker is
      # Jira; without supplying it here, building the panel raises NoMethodError (the context is
      # built manually, outside a request, so unset attributes have no reader) and the whole
      # catalog silently degrades to [].
      def jira_issues_integration?
        resource.jira_issues_integration_available? && resource.jira_integration&.issues_enabled
      end

      def entry_for(item)
        {
          id: item[:id],
          name: item[:title],
          description: item[:description]
        }.compact
      end
    end
  end
end
