# frozen_string_literal: true

module BillingPlansHelper
  include Gitlab::Utils::StrongMemoize
  include Gitlab::Allowable

  RETRIAL_CARD_CALLOUT = 'billing_retrial_card'
  POST_TRIAL_USAGE_CARD_CALLOUT = 'post_trial_usage_card'
  POST_TRIAL_USAGE_CARD_DURATION = 45.days

  def subscription_plan_info(plans_data, current_plan_code)
    current_plan = plans_data.find { |plan| plan.code == current_plan_code && plan.current_subscription_plan? }
    current_plan || plans_data.find { |plan| plan.code == current_plan_code }
  end

  def number_to_plan_currency(value)
    number_to_currency(value, unit: '$', strip_insignificant_zeros: true, format: "%u%n")
  end

  def show_contact_sales_button?(purchase_link_action)
    purchase_link_action == 'upgrade'
  end

  def show_upgrade_button?(purchase_link_action, allow_upgrade)
    return false if allow_upgrade == false

    purchase_link_action == 'upgrade'
  end

  # [namespace] can be either a namespace or a group
  def can_edit_billing?(namespace)
    can?(current_user, :edit_billing, namespace)
  end

  # [namespace] can be either a namespace or a group
  def subscription_plan_data_attributes(namespace, plan, read_only: false)
    return {} unless namespace

    {
      namespace_id: namespace.id,
      namespace_name: namespace.name,
      add_seats_href: add_seats_url(namespace),
      plan_renew_href: plan_renew_url(namespace),
      customer_portal_url: ::Gitlab::Routing.url_helpers.subscription_portal_manage_url,
      billable_seats_href: billable_seats_href(namespace),
      plan_name: plan&.name,
      read_only: read_only.to_s,
      seats_last_updated: seats_last_updated_value(namespace)
    }.tap do |attrs|
      if Feature.enabled?(:refresh_billings_seats, type: :ops)
        attrs[:refresh_seats_href] = refresh_seats_group_billings_url(namespace)
      end
    end
  end

  def free_trial_plan_billing_attributes(namespace, plans_data, monthly_commitment_purchased: 0)
    premium_plan = find_plan(plans_data, ::GitlabSubscriptions::SystemDefined::Plan::PREMIUM)
    ultimate_plan = find_plan(plans_data, ::GitlabSubscriptions::SystemDefined::Plan::ULTIMATE)

    total_seats =
      if ::Namespaces::FreeUserCap::Enforcement.new(namespace).enforce_cap?
        ::Namespaces::FreeUserCap.dashboard_limit
      else
        namespace.gitlab_subscription&.seats
      end

    eligible_for_trial = namespace.eligible_for_trial?

    {
      seatsInUse: namespace.gitlab_subscription&.seats_in_use,
      totalSeats: total_seats,
      trialActive: namespace.trial_active?,
      eligibleForTrial: eligible_for_trial,
      # A namespace that qualifies for a trial but has trialled before is by definition re-trial
      # eligible. Deriving it avoids a second CustomersDot eligibility lookup on page render.
      eligibleForRetrial: eligible_for_trial && !namespace.never_had_trial? && !post_trial_usage(namespace),
      canStartTrial: can_edit_billing?(namespace),
      retrialCardDismissed: retrial_card_dismissed?(namespace),
      retrialCardFeatureName: RETRIAL_CARD_CALLOUT,
      groupId: namespace.id,
      trialEndsOn: namespace.trial_ends_on&.strftime('%B %-d, %Y'),
      manageSeatsPath: group_usage_quotas_path(namespace, anchor: 'seats-quota-tab'),
      startTrialPath: new_trial_path(namespace_id: namespace.id),
      upgradeToPremiumUrl: plan_purchase_url(namespace, premium_plan),
      upgradeToUltimateUrl: plan_purchase_url(namespace, ultimate_plan),
      upgradeToPremiumTrackingUrl:
        track_cart_abandonment_gitlab_subscriptions_hand_raise_leads_path(
          namespace_id: namespace.id, plan: ::GitlabSubscriptions::SystemDefined::Plan::PREMIUM),
      upgradeToUltimateTrackingUrl:
        track_cart_abandonment_gitlab_subscriptions_hand_raise_leads_path(
          namespace_id: namespace.id, plan: ::GitlabSubscriptions::SystemDefined::Plan::ULTIMATE),
      purchaseCreditsTrackingUrl:
        track_cart_abandonment_gitlab_subscriptions_hand_raise_leads_path(
          namespace_id: namespace.id, credits: monthly_commitment_purchased),
      purchaseCreditsPath: ::Gitlab::Routing.url_helpers.subscription_portal_gitlab_com_purchase_credits_url(namespace.id),
      gitlabCreditsDashboardPath: group_settings_gitlab_credits_dashboard_index_path(namespace),
      monthlyCommitmentPurchased: monthly_commitment_purchased,
      postTrialUsage: post_trial_usage_card_data(namespace)
    }
  end

  def user_billing_data_attributes(plans_data)
    return { groups: [] } if plans_data.blank?

    premium_plan = find_plan(plans_data, ::GitlabSubscriptions::SystemDefined::Plan::PREMIUM)
    return { groups: [] } unless premium_plan

    groups = current_user.owned_groups
                         .free_or_trial
                         .not_aimed_for_deletion
                         .include_gitlab_subscription

    {
      groups: groups.map do |group|
        {
          id: group.id,
          name: group.name,
          trial_active: group.trial_active?,
          group_billings_href: group_billings_path(group),
          upgrade_to_premium_href: plan_purchase_url(group, premium_plan),
          can_access_duo_chat: Ability.allowed?(current_user, :access_duo_entry_point, group),
          explore_links: explore_links(group, group.all_projects.sorted_by_activity.first)
        }
      end,
      dashboardGroupsHref: dashboard_groups_path
    }
  end

  def plan_feature_list(plan)
    plans_features[plan.code] || []
  end

  def plan_purchase_or_upgrade_url(group, plan)
    if group.upgradable?
      plan_upgrade_url(group, plan)
    else
      plan_purchase_url(group, plan)
    end
  end

  def show_plans?(namespace)
    if namespace.free_personal?
      false
    elsif namespace.trial_active?
      true
    else
      !highest_tier?(namespace)
    end
  end

  def upgrade_button_css_classes(namespace, plan, is_current_plan)
    css_classes = []

    css_classes << 'disabled' if is_current_plan && !namespace.trial_active?
    css_classes << '!gl-invisible' if plan.deprecated?
    css_classes << "billing-cta-purchase#{'-new' unless namespace.upgradable?}"

    css_classes.join(' ')
  end

  def billing_available_plans(plans_data, current_plan)
    plans_data.reject do |plan_data|
      if plan_data.code == current_plan&.code
        plan_data.deprecated? && plan_data.hide_deprecated_card?
      else
        plan_data.deprecated?
      end
    end
  end

  def plan_purchase_url(group, plan)
    GitlabSubscriptions::PurchaseUrlBuilder.new(
      plan_id: plan.id,
      namespace: group
    ).build(source: params[:source])
  end

  def promotion_upgrade_to_premium_url(namespace, source:)
    root_namespace = namespace.root_ancestor
    plans_data = GitlabSubscriptions::FetchSubscriptionPlansService
      .new(plan: root_namespace.plan_name_for_upgrading, namespace_id: root_namespace.id)
      .execute
    premium_plan = plans_data&.find { |plan| plan.code == ::Plan::PREMIUM }

    # Personal namespaces can't hold a subscription. A nil namespace routes
    # to group selection/creation before checkout.
    purchase_namespace = root_namespace.user_namespace? ? nil : root_namespace

    GitlabSubscriptions::PurchaseUrlBuilder
      .new(plan_id: premium_plan&.id, namespace: purchase_namespace)
      .build(source: source)
  end

  def promotion_purchased_gitlab_credits?(namespace)
    GitlabSubscriptions::AddOnPurchase.purchased_gitlab_credits_exist?(namespace)
  end

  def billing_upgrade_button_data(plan)
    {
      track_action: 'click_button',
      track_label: 'upgrade',
      track_property: plan.code,
      testid: "upgrade-to-#{plan.code}"
    }
  end

  def trusted_by_logos
    [
      { name: 'T-Mobile', path: 'marketing/t-mobile.svg' },
      { name: 'Goldman Sachs', path: 'marketing/goldman-sachs.svg' },
      { name: 'Airbus', path: 'marketing/airbus.svg' },
      { name: 'NVIDIA', path: 'marketing/nvidia.svg' },
      { name: 'Carfax', path: 'marketing/carfax.svg', no_invert: true },
      { name: 'Lockheed Martin', path: 'marketing/lockheed-martin.svg' },
      { name: 'UBS', path: 'marketing/ubs.svg' }
    ]
  end

  private

  def retrial_card_dismissed?(namespace)
    return false unless current_user

    current_user.dismissed_callout_for_group?(feature_name: RETRIAL_CARD_CALLOUT, group: namespace)
  end

  def post_trial_usage(namespace)
    strong_memoize_with(:post_trial_usage, namespace) do
      next unless Feature.enabled?(:post_trial_usage_card, namespace)
      next unless ::GitlabSubscriptions::Trials.recently_expired?(namespace, time_frame: POST_TRIAL_USAGE_CARD_DURATION)

      ::GitlabSubscriptions::TrialUsage.find_for_trial(namespace.id, namespace.trial_ends_on)
    end
  end

  def post_trial_usage_card_data(namespace)
    trial_usage = post_trial_usage(namespace)
    return unless trial_usage
    return unless can_edit_billing?(namespace)
    return if current_user.dismissed_callout_for_group?(feature_name: POST_TRIAL_USAGE_CARD_CALLOUT, group: namespace)

    {
      seatsUsed: trial_usage.max_seats_used,
      computeMinutesUsed: trial_usage.compute_minutes_used,
      creditsUsed: trial_usage.credits_used&.to_f,
      freeSeatsLimit: ::Namespaces::FreeUserCap.dashboard_limit,
      freeComputeMinutesLimit: ::Gitlab::CurrentSettings.shared_runners_minutes,
      calloutFeatureName: POST_TRIAL_USAGE_CARD_CALLOUT
    }
  end

  def seats_last_updated_value(namespace)
    subscription = namespace.gitlab_subscription

    return unless subscription
    return unless subscription.last_seat_refresh_at

    namespace.gitlab_subscription.last_seat_refresh_at.utc.strftime('%H:%M:%S')
  end

  def add_seats_url(group)
    return unless group

    ::Gitlab::Routing.url_helpers.subscription_portal_add_extra_seats_url(group.id)
  end

  def duo_pro_url(group)
    return unless group

    ::Gitlab::Routing.url_helpers.subscription_portal_add_saas_duo_pro_seats_url(group.id)
  end

  def plan_upgrade_url(group, plan)
    return unless group && plan&.id

    ::Gitlab::Routing.url_helpers.subscription_portal_upgrade_subscription_url(group.id, plan.id)
  end

  def plan_renew_url(group)
    return unless group

    ::Gitlab::Routing.url_helpers.subscription_portal_renew_subscription_url(group.id)
  end

  def billable_seats_href(namespace)
    return unless namespace.group_namespace?

    group_usage_quotas_path(namespace, anchor: 'seats-quota-tab')
  end

  def highest_tier?(namespace)
    namespace.ultimate_plan? || namespace.opensource_plan?
  end

  def plans_features
    Hashie::Mash.new(
      free: [
        { title: s_('BillingPlans|Features include:'), highlight: true },
        { title: s_('BillingPlans|All stages of the DevOps lifecycle') },
        { title: s_('BillingPlans|Bring your own CI runners') },
        { title: s_('BillingPlans|Bring your own production environment') },
        { title: s_('BillingPlans|400 compute minutes') }
      ],
      premium: [
        { title: s_('BillingPlans|Everything from Free, plus:'), highlight: true },
        { title: s_('BillingPlans|Cross-team project management') },
        { title: s_('BillingPlans|Multiple approval rules') },
        { title: s_('BillingPlans|Multi-region support') },
        { title: s_('BillingPlans|Priority support') },
        { title: s_('BillingPlans|10000 compute minutes') },
        { title: s_('BillingPlans|GitLab Duo Agent Platform'), highlight: true },
        { title: s_('BillingPlans|Includes $12 in GitLab Credits per user per month') }
      ],
      ultimate: [
        { title: s_('BillingPlans|Everything from Premium, plus:'), highlight: true },
        { title: s_('BillingPlans|Company wide portfolio management') },
        { title: s_('BillingPlans|Advanced application security') },
        { title: s_('BillingPlans|Executive level insights') },
        { title: s_('BillingPlans|Compliance automation') },
        { title: s_('BillingPlans|Free guest users') },
        { title: s_('BillingPlans|50000 compute minutes') },
        { title: s_('BillingPlans|GitLab Duo Agent Platform'), highlight: true },
        { title: s_('BillingPlans|Includes $24 in GitLab Credits per user per month') }
      ]
    )
  end

  def find_plan(plans_data, plan_code)
    plans_data.find { |plan| plan.code == plan_code }
  end

  def explore_links(namespace, project)
    project_settings_links = if project
                               {
                                 mergeTrains: project_settings_merge_requests_path(project),
                                 escalationPolicies: project_incident_management_escalation_policies_path(project),
                                 repositoryPullMirroring: project_settings_repository_path(project, anchor: "js-push-remote-settings"),
                                 mergeRequestApprovals: project_settings_merge_requests_path(project, anchor: "js-merge-request-approval-settings")
                               }
                             else
                               { mergeTrains: nil, escalationPolicies: nil, repositoryPullMirroring: nil, mergeRequestApprovals: nil }
                             end

    {
      duoChat: Ability.allowed?(current_user, :access_duo_entry_point, namespace) ? nil : group_settings_gitlab_duo_seat_utilization_index_path(namespace),
      epics: group_epics_path(namespace)
    }.merge(project_settings_links)
  end
end

BillingPlansHelper.prepend_mod
