# frozen_string_literal: true

module SeatAlert
  class NamespaceComponent < BaseComponent
    include Gitlab::Utils::StrongMemoize

    COMPONENT_BY_STATE = {
      threshold: Namespace::ThresholdComponent,
      reached: Namespace::ReachedComponent,
      overage: Namespace::OverageComponent
    }.freeze

    CALLOUT_FEATURE_NAME_BY_STATE = {
      threshold: Users::GroupCalloutsHelper::APPROACHING_SEAT_COUNT_THRESHOLD,
      reached: Users::GroupCalloutsHelper::REACHED_SEAT_COUNT_THRESHOLD,
      overage: Users::GroupCalloutsHelper::OVERAGE_SEAT_COUNT_THRESHOLD
    }.freeze

    def initialize(context:, current_user:)
      @root_namespace = context.root_ancestor
      @current_user = current_user
    end

    def render?
      return false unless ::Gitlab::Saas.feature_available?(:gitlab_com_subscriptions)
      return false unless root_namespace.group_namespace?
      return false unless can_read_subscription_usage?
      return false unless current_subscription
      return false if small_subscription?
      return false unless billable_members_count
      return false unless show_alert?
      return false if dismissed_callout?

      true
    end

    private

    attr_reader :root_namespace, :current_user

    def remaining_user_count
      total_user_count - billable_members_count
    end

    def total_user_count
      current_subscription.seats
    end

    def billable_members_count
      root_namespace.billable_members_count_with_reactive_cache
    end
    strong_memoize_attr :billable_members_count

    def current_subscription
      subscription = root_namespace.gitlab_subscription

      return unless subscription
      return unless subscription.has_a_paid_hosted_plan?
      return if subscription.expired?

      subscription
    end
    strong_memoize_attr :current_subscription

    def can_read_subscription_usage?
      Ability.allowed?(current_user, :read_subscription_usage, root_namespace)
    end

    def show_alert?
      return true if billable_members_count >= total_user_count

      ::GitlabSubscriptions::SeatThresholds.threshold_reached?(
        seats_total: total_user_count,
        seats_used: billable_members_count
      )
    end

    def render_component
      self.class::COMPONENT_BY_STATE.fetch(seat_state).new(
        root_namespace: root_namespace,
        current_user: current_user,
        remaining_seat_count: remaining_user_count,
        total_seat_count: total_user_count
      )
    end

    def dismissed_callout?
      current_user.dismissed_callout_for_group?(
        feature_name: self.class::CALLOUT_FEATURE_NAME_BY_STATE.fetch(seat_state),
        group: root_namespace
      )
    end
  end
end
