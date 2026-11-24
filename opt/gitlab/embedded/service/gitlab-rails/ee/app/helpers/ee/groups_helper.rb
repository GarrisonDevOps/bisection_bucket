# frozen_string_literal: true

module EE
  module GroupsHelper
    extend ::Gitlab::Utils::Override
    include ::Gitlab::Utils::StrongMemoize
    include ::Nav::GitlabDuoSettingsPage

    def size_limit_message_for_group(group)
      repository_size_limit_link = link_to _('Learn more'), help_page_path('administration/settings/account_and_limit_settings.md', anchor: 'repository-size-limit')
      message = group.lfs_enabled? ? _("Max size for repositories within this group, including LFS files. %{repository_size_limit_link}.") : _("Max size for repositories within this group. %{repository_size_limit_link}.")

      safe_format(message, repository_size_limit_link: repository_size_limit_link)
    end

    override :group_general_settings_data
    def group_general_settings_data(group)
      can_edit_repository_size_limit = current_user.can_admin_all_resources? &&
        License.feature_available?(:repository_size_limit)

      super.merge(
        can_edit_repository_size_limit: can_edit_repository_size_limit.to_s,
        repository_size_limit_value: can_edit_repository_size_limit ? group.repository_size_limit.try(:to_mb) : nil,
        repository_size_limit_help_text: can_edit_repository_size_limit ? size_limit_message_for_group(group) : ''
      )
    end

    override :subgroup_creation_data
    def subgroup_creation_data(group)
      super.merge({
        identity_verification_required: current_user.requires_identity_verification_to_create_group?(group).to_s,
        identity_verification_path: identity_verification_path,
        enforce_top_level_group_limit: current_user.enforce_top_level_group_limit?.to_s
      })
    end

    def show_plan_indicator?(group)
      ::Gitlab::Saas.feature_available?(:gitlab_com_subscriptions) &&
        group.root? &&
        group.trial?
    end

    def show_discover_group_security?(group)
      !!current_user &&
        ::Gitlab.com? &&
        !group.licensed_feature_available?(:security_dashboard) &&
        can?(current_user, :admin_group, group)
    end

    def show_group_activity_analytics?
      can?(current_user, :read_group_activity_analytics, @group)
    end

    def show_product_purchase_success_alert?
      !params[:purchased_product].blank?
    end

    def show_user_cap_alert?
      root_namespace = @group.root_ancestor

      return false unless root_namespace.present? &&
        can?(current_user, :admin_group, root_namespace) &&
        root_namespace.user_cap_available? &&
        root_namespace.namespace_settings.present?

      root_namespace.user_cap_enabled?
    end

    def pending_members_link
      link_to('', pending_members_group_usage_quotas_path(@group.root_ancestor))
    end

    def group_seats_usage_quota_app_data(group)
      {
        namespace_id: group.id,
        namespace_name: group.name,
        is_public_namespace: group.public?.to_s,
        full_path: group.full_path,
        seat_usage_export_path: group_seat_usage_path(group, format: :csv),
        subscription_history_href: subscription_history_group_usage_quotas_path(group),
        add_seats_href: add_seats_url(group),
        max_free_namespace_seats: ::Namespaces::FreeUserCap.dashboard_limit,
        explore_plans_path: group_billings_path(group),
        enforcement_free_user_cap_enabled: ::Namespaces::FreeUserCap::Enforcement.new(group).enforce_cap?.to_s,
        trial_duration: ::GitlabSubscriptions::TrialDurationService.new.execute
      }
    end

    def duo_home_app_data(group)
      settings = group.namespace_settings

      {
        duo_seat_utilization_path: group_settings_gitlab_duo_seat_utilization_index_path(group),
        duo_availability: settings.duo_availability.to_s,
        experiment_features_enabled: settings.experiment_features_enabled.to_s,
        prompt_cache_enabled: settings.model_prompt_cache_enabled.to_s,
        are_experiment_settings_allowed: group.experiment_settings_allowed?.to_s,
        are_prompt_cache_settings_allowed: group.prompt_cache_settings_allowed?.to_s,
        duo_configuration_path: group_settings_gitlab_duo_configuration_index_path(group),
        duo_governance_path: group_automate_governance_path(group),
        are_duo_core_features_enabled: settings.duo_core_features_enabled.to_s,
        duo_remote_flows_availability: settings.duo_remote_flows_availability.to_s,
        duo_foundational_flows_availability: settings.duo_foundational_flows_availability.to_s,
        model_switching_enabled: can?(current_user, :admin_group_model_selection, group).to_s,
        model_switching_path: group_settings_gitlab_duo_model_selection_index_path(group),
        gitlab_credits_dashboard_path: gitlab_credits_dashboard_path(group),
        credits_generalization_ui: ::Feature.enabled?(:credits_generalization_ui, group).to_s
      }.merge(dap_monthly_commit_promo_data(group), code_suggestions_usage_app_data(group))
    end

    def code_suggestions_usage_app_data(group)
      {
        full_path: group.full_path,
        group_id: group.id,
        add_duo_pro_href: duo_pro_url(group),
        duo_pro_bulk_user_assignment_available: 'true',
        hand_raise_lead: code_suggestions_usage_app_hand_raise_lead_data,
        is_free_namespace: group.has_free_or_no_subscription?.to_s,
        buy_subscription_path: group_billings_path(group),
        duo_page_path: group_settings_gitlab_duo_path(group)
      }.merge(active_duo_add_on_data(group), active_subscription_data(group))
    end

    def active_subscription_data(group)
      return {} unless group_gitlab_subscription(group)

      {
        subscription_start_date: group_gitlab_subscription(group).start_date,
        subscription_end_date: group_gitlab_subscription(group).end_date
      }
    end

    def group_gitlab_subscription(group)
      strong_memoize(:group_gitlab_subscription) do
        group.gitlab_subscription
      end
    end

    def active_duo_add_on_data(group)
      active_duo_add_on = group.subscription_add_on_purchases.for_duo_pro_or_duo_enterprise.active.first

      return {} unless active_duo_add_on

      duo_add_on_end_date = if active_duo_add_on.trial?
                              active_duo_add_on.expires_on
                            else
                              # When the purchase is not a trial, we add the 14-day grace
                              # period to expires_on. For displaying purposes, we subtract
                              # the grace period to show the correct end date.
                              active_duo_add_on.expires_on - SUBSCRIPTION_GRACE_PERIOD
                            end

      {
        duo_add_on_is_trial: active_duo_add_on.trial?.to_s,
        duo_add_on_start_date: active_duo_add_on.started_at,
        duo_add_on_end_date: duo_add_on_end_date
      }
    end

    def show_usage_quotas_tab?(group, tab)
      case tab
      when :seats
        License.feature_available?(:seat_usage_quotas)
      when :code_suggestions
        show_gitlab_duo_settings_app?(group)
      when :pipelines
        Ability.allowed?(current_user, :read_compute_minutes, group) &&
          License.feature_available?(:pipelines_usage_quotas)
      when :transfer
        ::Feature.enabled?(:data_transfer_monitoring, group) &&
          License.feature_available?(:transfer_usage_quotas)
      when :pages
        group.root_ancestor == group && License.feature_available?(:pages_multiple_versions)
      else
        false
      end
    end

    def saml_sso_settings_generate_helper_text(display_none:, text:)
      content_tag(:span, text, class: ['js-helper-text', 'gl-clearfix', ('gl-hidden' if display_none)])
    end

    def group_transfer_app_data(group)
      {
        full_path: group.full_path
      }
    end

    def pages_deployments_app_data(group)
      limit = group.actual_limits.active_versioned_pages_deployments_limit_by_namespace
      count_by_project = ::PagesDeployment.count_versioned_deployments_for(
        group.all_projects,
        limit,
        group_by_project: true,
        namespace_domain_only: true
      )

      {
        full_path: group.full_path,
        deployments_count: count_by_project.values.sum,
        deployments_limit: limit,
        # rubocop: disable CodeReuse/ActiveRecord -- Limited re-usability for this pluck
        deployments_by_project: group.all_projects.id_in(count_by_project.keys).pluck(:id, :name).map do |id, name|
          {
            name: name,
            count: count_by_project[id]
          }
        end.to_json
        # rubocop: enable CodeReuse/ActiveRecord
      }
    end

    private

    SUBSCRIPTION_GRACE_PERIOD = 14.days
    private_constant :SUBSCRIPTION_GRACE_PERIOD

    def gitlab_credits_dashboard_available?(group)
      return false unless ::Gitlab::Saas.feature_available?(:gitlab_com_subscriptions)

      group.gitlab_credits_entitled?
    end

    def gitlab_credits_dashboard_path(group)
      return if ::Feature.enabled?(:hide_gitlab_credits_page, group) &&
        group.plan_name_for_upgrading == ::GitlabSubscriptions::SystemDefined::Plan::FREE

      return unless gitlab_credits_dashboard_available?(group)

      group_settings_gitlab_credits_dashboard_index_path(group)
    end

    def dap_monthly_commit_promo_data(group)
      {
        gitlab_com_purchase_credits_path: ::Gitlab::Routing.url_helpers.subscription_portal_gitlab_com_purchase_credits_url(group.id),
        namespace_is_on_trial: group.trial_active?.to_s
      }
    end
  end
end
