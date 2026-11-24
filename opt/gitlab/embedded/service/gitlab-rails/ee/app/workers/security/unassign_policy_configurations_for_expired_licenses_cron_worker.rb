# frozen_string_literal: true

module Security
  class UnassignPolicyConfigurationsForExpiredLicensesCronWorker
    include ApplicationWorker
    include CronjobQueue
    include Gitlab::Utils::StrongMemoize

    idempotent!
    data_consistency :sticky
    feature_category :security_policy_management

    BATCH_SIZE = 100
    BUFFER_PERIOD = 3.days
    MAX_RUNTIME = 3.minutes
    REQUEUE_DELAY = 3.minutes

    def perform(cursor = nil)
      if saas?
        handle_saas
      else
        handle_self_managed(cursor)
      end
    end

    private

    def saas?
      ::Gitlab::Saas.feature_available?(:gitlab_com_subscriptions)
    end

    def handle_saas
      expired_ultimate_subscriptions.find_each(batch_size: BATCH_SIZE) do |subscription| # rubocop:disable CodeReuse/ActiveRecord -- the logic is specific to this worker
        namespace = subscription.namespace
        next unless namespace

        next if active_ultimate_subscription?(namespace.gitlab_subscription)

        schedule_unassign_worker_for_namespace(namespace)
      end
    end

    def expired_ultimate_subscriptions
      GitlabSubscriptions::SubscriptionHistory
        .ended_on(buffer_date)
        .with_all_ultimate_plans
        .with_namespace_subscription
    end

    def active_ultimate_subscription?(subscription)
      return false unless subscription && !subscription.expired?

      ultimate_plan_uids.include?(subscription.hosted_plan_name_uid)
    end

    def ultimate_plan_uids
      ::GitlabSubscriptions::SystemDefined::Plan.uids_for_names(::GitlabSubscriptions::SystemDefined::Plan::ALL_ULTIMATE_PLANS)
    end
    strong_memoize_attr :ultimate_plan_uids

    def handle_self_managed(cursor)
      return if Security::OrchestrationPolicyConfiguration.none?
      return if active_license_within_buffer_date?

      runtime_limiter = Gitlab::Metrics::RuntimeLimiter.new(MAX_RUNTIME)

      Namespace.top_level.where('id > ?', cursor || 0).each_batch(of: BATCH_SIZE) do |batch| # rubocop:disable CodeReuse/ActiveRecord -- the logic is specific to this worker
        batch.each { |namespace| schedule_unassign_worker_for_namespace(namespace) }

        if runtime_limiter.over_time?
          self.class.perform_in(REQUEUE_DELAY, batch.last.id)
          break
        end
      end
    end

    def active_license_within_buffer_date?
      license = License.current || License.history.first
      return false if license.blank?
      return true if active_ultimate_license?(license)

      comparison_date = license.expired? ? license.expires_at : license.starts_at
      comparison_date > buffer_date
    end

    def schedule_unassign_worker_for_namespace(namespace)
      with_context(namespace: namespace) do
        Security::UnassignPolicyConfigurationsForExpiredNamespaceWorker.perform_async(namespace.id)
      end
    end

    def active_ultimate_license?(license)
      license.active? && license.ultimate?
    end

    def buffer_date
      Date.current.days_ago((GitlabSubscription::SUBSCRIPTION_GRACE_PERIOD + BUFFER_PERIOD))
    end
  end
end
