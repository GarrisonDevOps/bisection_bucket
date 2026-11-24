# frozen_string_literal: true

module ServiceDesk
  # Newly paid namespaces keep the free plan Service Desk email limits for a
  # configurable number of days. Opting a namespace out of the feature flag
  # (`value=opt_out`) lifts its probation immediately.
  class PaidNamespaceProbation
    class << self
      # Self-managed licenses cover the whole instance, so there are no
      # per-namespace subscriptions to put on probation.
      #
      # @return [Boolean]
      def available?
        ::Gitlab::Saas.feature_available?(:gitlab_com_subscriptions)
      end

      # Whether the Admin area shows the probation length setting.
      #
      # @return [Boolean]
      def configurable?
        available? &&
          ::Feature.enabled?(:service_desk_paid_namespace_probation, type: :wip) # rubocop:disable Gitlab/FeatureFlagWithoutActor -- no actor: true only when the flag is enabled globally, not during a percentage rollout
      end
    end

    # @param root_namespace [Namespace]
    def initialize(root_namespace)
      @root_namespace = root_namespace
    end

    # @return [Boolean] true when the namespace should get free plan email limits
    def active?
      ::Gitlab::SafeRequestStore.fetch(request_store_key) { probation_active? }
    end

    private

    attr_reader :root_namespace

    def probation_active?
      return false unless self.class.available?
      # Open source program namespaces are approved by GitLab, not purchased.
      return false unless root_namespace.actual_plan.paid_excluding_trials?(exclude_oss: true)
      return false unless ::Feature.enabled?(:service_desk_paid_namespace_probation, root_namespace, type: :wip)
      return false if probation_days == 0

      became_paid_since?(probation_days.days.ago)
    end

    # Not start_date, which moves forward on every renewal. History rows store
    # the state a change replaced, so an unpaid row marks an upgrade.
    def became_paid_since?(window_start)
      return true if root_namespace.gitlab_subscription.created_at.after?(window_start)

      root_namespace.gitlab_subscription_histories
        .without_paid_plan_excluding_trials
        .created_since(window_start)
        .exists?
    end

    def probation_days
      ::Gitlab::CurrentSettings.service_desk_paid_namespace_probation_days
    end

    def request_store_key
      "namespaces:#{root_namespace.id}:service_desk_paid_namespace_probation"
    end
  end
end
