# frozen_string_literal: true

module GitlabSubscriptions
  module Trials
    class CaptureUsageService
      MONTHLY_RATE_DAYS = 30
      MIN_DAYS_IN_END_MONTH = 7

      def initialize(gitlab_subscription)
        @gitlab_subscription = gitlab_subscription
        @namespace = gitlab_subscription.namespace
      end

      def execute
        return ServiceResponse.error(message: 'Subscription is not a trial', reason: :not_a_trial) unless trial?

        attributes = snapshot_attributes
        merge_existing_snapshot!(attributes)

        GitlabSubscriptions::TrialUsage.upsert(attributes, unique_by: %i[namespace_id trial_ends_on])

        ServiceResponse.success(payload: attributes)
      end

      private

      attr_reader :gitlab_subscription, :namespace

      # A failed CustomersDot read on the second capture must not lose the credits the first one stored.
      def merge_existing_snapshot!(attributes)
        existing = GitlabSubscriptions::TrialUsage.find_for_trial(namespace.id, gitlab_subscription.trial_ends_on)
        return unless existing

        attributes[:credits_used] = existing.credits_used if attributes[:credits_used].nil?
      end

      # Mirrors check_trial_usages_trial_ends_on_after_starts_on, which upsert would otherwise hit on every retry.
      def trial?
        gitlab_subscription.trial? &&
          gitlab_subscription.trial_starts_on &&
          gitlab_subscription.trial_ends_on &&
          gitlab_subscription.trial_ends_on > gitlab_subscription.trial_starts_on
      end

      def snapshot_attributes
        month = compute_month

        {
          namespace_id: namespace.id,
          trial_starts_on: gitlab_subscription.trial_starts_on,
          trial_ends_on: gitlab_subscription.trial_ends_on,
          trial_type: trial_type,
          max_seats_used: gitlab_subscription.max_seats_used.to_i,
          compute_minutes_used: monthly_compute_rate(month),
          compute_minutes_month: month,
          credits_used: credits_used
        }
      end

      # Compute minutes only exist as calendar-month totals, so the month is extrapolated to a 30-day
      # rate that the card can set against monthly quotas.
      def monthly_compute_rate(month)
        used = ::Ci::Minutes::NamespaceMonthlyUsage.by_namespace_and_date(namespace, month).sum(:amount_used).to_i
        return 0 if used == 0

        (used * MONTHLY_RATE_DAYS.to_f / elapsed_days_in(month)).round
      end

      # Falls back a month so the rate never rests on a day or two of usage.
      def compute_month
        end_month = gitlab_subscription.trial_ends_on.beginning_of_month
        return end_month if gitlab_subscription.trial_ends_on.day >= MIN_DAYS_IN_END_MONTH

        end_month.prev_month
      end

      # Captures run at 01:00 UTC, so the month's total covers the days before today.
      def elapsed_days_in(month)
        last_day = [Date.current - 1, month.end_of_month].min

        [(last_day - month).to_i + 1, 1].max
      end

      def trial_type
        if gitlab_subscription.plan_name == ::GitlabSubscriptions::SystemDefined::Plan::ULTIMATE_TRIAL_PAID_CUSTOMER
          PREMIUM_TRIAL_TYPE_V2
        else
          FREE_TRIAL_TYPE_V2
        end
      end

      # A failed CustomersDot read must not lose the seats and compute figures, so credits
      # are stored as unknown instead of aborting the snapshot.
      def credits_used
        client = ::Gitlab::SubscriptionPortal::SubscriptionUsageClient.new(namespace_id: namespace.id)

        client.get_trial_usage.dig(:trialUsage, :usersUsage, :creditsUsed)
      rescue ::Gitlab::SubscriptionPortal::SubscriptionUsageClient::ResponseError
        nil
      rescue *::Gitlab::HTTP::HTTP_ERRORS => e
        ::Gitlab::ErrorTracking.track_exception(e, namespace_id: namespace.id)
        nil
      end
    end
  end
end
