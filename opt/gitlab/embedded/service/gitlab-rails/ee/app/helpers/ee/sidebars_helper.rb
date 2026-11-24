# frozen_string_literal: true

module EE
  module SidebarsHelper
    extend ::Gitlab::Utils::Override

    override :project_sidebar_context_data
    def project_sidebar_context_data(project, user, current_ref, **args)
      super.merge({
        show_promotions: show_promotions?(user),
        show_discover_project_security: show_discover_project_security?(project)
      })
    end

    override :group_sidebar_context_data
    def group_sidebar_context_data(group, user)
      super.merge(
        show_promotions: show_promotions?(user),
        show_discover_group_security: show_discover_group_security?(group)
      )
    end

    override :your_work_context_data
    def your_work_context_data(user)
      super.merge({
        show_security_dashboard: security_dashboard_available?
      })
    end

    override :super_sidebar_context
    def super_sidebar_context(user, group:, project:, panel:, panel_type:)
      return super unless user

      context = super
      root_namespace = (project || group)&.root_ancestor

      context.merge!(
        ::GitlabSubscriptions::Trials::WidgetPresenter.new(root_namespace, user: current_user).attributes,
        ::GitlabSubscriptions::UpgradePresenter.new(user, namespace: root_namespace, project: project).attributes
      )

      if ::Feature.enabled?(:explore_analytics_dashboards, user)
        context[:analytics_dashboards_path] = explore_analytics_dashboards_path(organization_path: nil)
      end

      explore_premium_eligibility = ::GitlabSubscriptions::PaintedDoorRequestEligibility.new(
        user: user, namespace: root_namespace, feature: :explore_premium
      )

      if explore_premium_eligibility.eligible?
        context[:explore_premium] = {
          group_id: explore_premium_eligibility.root.id,
          requested: explore_premium_eligibility.requested?
        }
      end

      show_buy_pipeline_minutes = show_buy_pipeline_minutes?(project, group)

      return context unless show_buy_pipeline_minutes && root_namespace.present?

      context.merge({
        pipeline_minutes: {
          show_buy_pipeline_minutes: show_buy_pipeline_minutes,
          show_notification_dot: show_pipeline_minutes_notification_dot?(project, group),
          show_with_subtext: show_buy_pipeline_with_subtext?(project, group),
          buy_pipeline_minutes_path: usage_quotas_path(root_namespace),
          tracking_attrs: {
            'track-action': 'click_buy_ci_minutes',
            'track-label': root_namespace.actual_plan_name,
            'track-property': 'user_dropdown'
          },
          notification_dot_attrs: {
            'data-track-action': 'render',
            'data-track-label': 'show_buy_ci_minutes_notification',
            'data-track-property': current_user.namespace.actual_plan_name
          },
          callout_attrs: {
            feature_id: ::Ci::RunnersHelper::BUY_PIPELINE_MINUTES_NOTIFICATION_DOT,
            dismiss_endpoint: callouts_path
          }
        }
      })
    end

    override :compare_plans_url
    def compare_plans_url(user: nil, project: nil, group: nil)
      return super unless user

      target_group = group if group&.persisted?
      target_group ||= project.namespace if project&.persisted? && project.namespace.is_a?(Group)

      if target_group && can?(user, :read_billing, target_group)
        group_billings_path(target_group)
      else
        promo_pricing_url
      end
    end

    override :super_sidebar_logged_out_context
    def super_sidebar_logged_out_context(panel:, panel_type:)
      context = super

      return context unless ::Gitlab::Saas.feature_available?(:gitlab_com_subscriptions)

      context.merge({
        trial_registration_path: new_trial_registration_path(organization_path: nil)
      })
    end

    override :super_sidebar_logged_in_context
    def super_sidebar_logged_in_context(user, group:, project:, panel:, panel_type:)
      # Project pages have no group in scope, so the project's root group has to be
      # resolved here. Otherwise the presenter falls back to the user's own namespaces.
      upgrade_link_group = group || project&.root_group

      super.merge(
        ::GitlabSubscriptions::FreeGroupUpgradeLinkPresenter.new(user, group: upgrade_link_group).attributes
      )
    end

    private

    # Avoid duplicating "Work Items" on the frontend now that
    # :group_issue_list and :group_epic_list are translated in the frontend.
    override :pinned_items
    def pinned_items(user, panel_type, group: nil, saved_pins: user.pinned_nav_items)
      items = super

      return items unless group

      if items.include?("group_issue_list") && items.include?("group_epic_list")
        items.excluding("group_epic_list")
      else
        items
      end
    end

    override :super_sidebar_default_pins
    def super_sidebar_default_pins(panel_type)
      case panel_type
      when 'group'
        super + %w[group_epic_list epic_boards]
      else
        super
      end
    end
  end
end
