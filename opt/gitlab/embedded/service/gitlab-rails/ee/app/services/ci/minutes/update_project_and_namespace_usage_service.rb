# frozen_string_literal: true

module Ci
  module Minutes
    class UpdateProjectAndNamespaceUsageService
      include Gitlab::Utils::StrongMemoize

      IDEMPOTENCY_CACHE_TTL = 12.hours

      def initialize(project_id, namespace_id, build_id)
        @project_id = project_id
        @namespace_id = namespace_id
        @build_id = build_id
        # TODO(issue 335885): Use project_id only and don't query for projects which may be deleted
        @project = Project.find_by_id(project_id)
      end

      # Updates the project and namespace usage based on the passed consumption amount
      def execute(consumption, duration = nil)
        ensure_idempotency { track_monthly_usage(consumption, duration.to_i) }

        # No need to check notification if consumption hasn't changed
        send_minutes_email_notification if consumption > 0
      end

      def idempotency_cache_key
        "ci_minutes_usage:#{@project_id}:#{@build_id}:updated"
      end

      private

      # We want to rescue and track exceptions to ensure the service
      # remains idempotent. Sending email notifications is not as critical
      # as this service idempotency.
      # TODO: we should move this to be an async job.
      # https://gitlab.com/gitlab-org/gitlab/-/issues/335885
      def send_minutes_email_notification
        # TODO(issue 335885): Remove @project
        ::Ci::Minutes::EmailNotificationService.new(@project.reset).execute if ::Gitlab.com?
      rescue StandardError => e
        ::Gitlab::ErrorTracking.track_and_raise_for_dev_exception(e,
          project_id: @project_id,
          namespace_id: @namespace_id,
          build_id: @build_id)
      end

      def track_monthly_usage(consumption, duration)
        # preload minutes usage data outside of transaction
        usages = [project_usage, namespace_usage].compact

        ::Ci::Minutes::NamespaceMonthlyUsage.transaction do
          usages.each { |usage| usage.increase_usage(amount_used: consumption, shared_runners_duration: duration) }
        end
      end

      def namespace_usage
        strong_memoize(:namespace_usage) do
          ::Ci::Minutes::NamespaceMonthlyUsage.find_or_create_current_shard(
            namespace_id: @namespace_id, build_id: @build_id)
        end
      end

      def project_usage
        strong_memoize(:project_usage) do
          if @project.present?
            ::Ci::Minutes::ProjectMonthlyUsage.find_or_create_current(project_id: @project_id)
          end
        end
      end

      # Ensure we only add the compute usage once for the given build
      # even if the worker is retried.
      # TODO: consolidate with the implementation in ::Ci::Minutes::GitlabHostedRunnerMonthlyUsageService
      # https://gitlab.com/gitlab-org/gitlab/-/issues/533876
      def ensure_idempotency
        if already_completed?
          ::Gitlab::AppJsonLogger.info(event: 'ci_minutes_consumption_already_updated', build_id: @build_id)
          return
        end

        yield

        mark_as_completed!
      end

      def mark_as_completed!
        Gitlab::Redis::SharedState.with do |redis|
          redis.set(idempotency_cache_key, 1, ex: IDEMPOTENCY_CACHE_TTL)
        end
      end

      def already_completed?
        Gitlab::Redis::SharedState.with do |redis|
          redis.exists?(idempotency_cache_key) # rubocop:disable CodeReuse/ActiveRecord
        end
      end
    end
  end
end
