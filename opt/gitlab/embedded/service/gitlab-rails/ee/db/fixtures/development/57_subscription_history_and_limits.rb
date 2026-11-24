# frozen_string_literal: true

# Seeds the subscription history, reconciliation and plan limit tables, which are empty in the
# upgrade stop dump, so migrations touching them were never exercised by
# db:migrate:multi-version-upgrade.
class Gitlab::Seeder::SubscriptionHistoryAndLimits # rubocop:disable Style/ClassAndModuleChildren -- seeder convention
  SEEDED_MAX_SEATS_USED = 7

  attr_reader :organization

  def initialize
    @organization = ::Gitlab::DatabaseImporters::AdminOrganizationImporter.seeded_admin_organization
  end

  # Each table hangs off a different parent, so each one is guarded on its own.
  def seed!
    seed_subscription_history
    seed_upcoming_reconciliation
    seed_plan_limits
  end

  private

  # The history row is written by the subscription's own `before_update` callback rather than
  # directly, so changing a tracked attribute is what produces the row the application would.
  def seed_subscription_history
    subscription = GitlabSubscription.order(:id).first
    return if subscription.nil? ||
      GitlabSubscriptions::SubscriptionHistory.exists?(gitlab_subscription_id: subscription.id)

    subscription.update!(max_seats_used: SEEDED_MAX_SEATS_USED)
    print '.'
  end

  # `namespace_id` is null on a self-managed instance, which is the row `UpcomingReconciliation.next`
  # reads there. A SaaS simulating instance validates its presence, so it takes the subscription's.
  def seed_upcoming_reconciliation
    return if organization.nil?

    namespace = GitlabSubscription.order(:id).first&.namespace if saas_subscriptions?
    return if saas_subscriptions? && namespace.nil?
    return if GitlabSubscriptions::UpcomingReconciliation.exists?(namespace_id: namespace&.id)

    GitlabSubscriptions::UpcomingReconciliation.create!(
      organization: namespace&.organization || organization, namespace: namespace,
      next_reconciliation_date: Date.current + 1.week, display_alert_from: Date.current - 1.day)
    print '.'
  end

  def saas_subscriptions?
    ::Gitlab::Saas.feature_available?(:gitlab_com_subscriptions)
  end

  # `plan_name_uid` is the authoritative write input and `before_save` derives `plan_id` from it,
  # so the row is built through the plan's own accessor rather than written column by column.
  def seed_plan_limits
    plan = ::GitlabSubscriptions::SystemDefined::Plan.default
    return if PlanLimits.exists?(plan_name_uid: plan.id)

    plan.actual_limits.save!
    print '.'
  end
end

Gitlab::Seeder.quiet do
  puts "\nGenerating subscription history and plan limit data"

  Gitlab::Seeder::SubscriptionHistoryAndLimits.new.seed!
end
