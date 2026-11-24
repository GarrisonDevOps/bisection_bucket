# frozen_string_literal: true

module Authz
  module ProjectAuthorizations
    # Drains authz_refresh_events one lease at a time. Namespace and share events are expanded. Other events are
    # recalculated once their compute flag is on, then finished, or continued from where the runtime ran out.
    # Until then they're dropped, or handed to the old Sidekiq workers while their group's Sidekiq flag is off.
    class RefreshService
      include Gitlab::Loggable

      # How long one lease may write for. A lease hides its events for twice this, so a crashed worker's
      # events come back on their own.
      LEASE_LIMIT = 1.minute
      USER_TARGET_TYPES = %i[user_in_project user_in_group user].freeze

      # @param runtime_limiter [Gitlab::Metrics::RuntimeLimiter] the job's own limit
      # @param poll_interval [ActiveSupport::Duration, nil] how long to wait on an empty queue before leasing
      #   again; nil returns as soon as the queue is empty
      def initialize(runtime_limiter, poll_interval: nil)
        @runtime_limiter = runtime_limiter
        @poll_interval = poll_interval
        expansion_types = RefreshEvent::EXPANSION_TYPES.map(&:to_s)
        computed_types = RefreshEvent.target_types.keys - expansion_types
        @counts = {
          finished: computed_types.index_with(0),
          continued: computed_types.index_with(0),
          dropped: computed_types.index_with(0),
          handed_off: computed_types.index_with(0),
          expanded: expansion_types.index_with(0),
          failed: RefreshEvent.target_types.keys.index_with(0)
        }
      end

      # @return [ServiceResponse] payload has :drained, and event counts by target type for each outcome:
      #   :finished_counts, :continued_counts, :dropped_counts, :handed_off_counts, :expanded_counts and
      #   :failed_counts
      def execute
        while time_for_another_lease?
          lease = RefreshEvent.lease(duration: LEASE_LIMIT * 2)

          if lease
            process(lease)
          elsif poll_interval
            sleep(poll_interval)
          else
            return response(drained: true)
          end
        end

        response(drained: false)
      end

      private

      attr_reader :runtime_limiter, :poll_interval, :counts

      # A lease must fit in what's left of the job, so a normal job end never leaves one behind.
      def time_for_another_lease?
        runtime_limiter.max_runtime - runtime_limiter.elapsed_time >= LEASE_LIMIT
      end

      # The context puts the lease's user and root namespace on its log line, its errors and any job it queues.
      def process(lease)
        Gitlab::ApplicationContext.with_context(context_for(lease)) do
          process_or_retry(lease)
        rescue RefreshEvent::LeaseLostError
          # The lease expired and another worker took its events over, so it owns their work now.
          log_lease(lease, 'Lost project authorization refresh lease')
        end
      rescue Sidekiq::Shutdown
        RefreshEvent.release(lease)
        raise
      end

      def process_or_retry(lease)
        if RefreshEvent::EXPANSION_TYPES.include?(lease.target_type)
          expand(lease)
        elsif RefreshEvent.computed?(lease.target_type, lease.actor_id)
          compute(lease)
        else
          hand_off_or_drop(lease)
        end
      rescue RefreshEvent::LeaseLostError
        raise
      rescue StandardError => e
        Gitlab::ErrorTracking.track_exception(e, target_type: lease.target_type, target_id: lease.target_id,
          scope_id: lease.scope_id, attempts: lease.attempts)
        RefreshEvent.fail(lease)
        count(:failed, lease)
      end

      def expand(lease)
        events = ExpandService.new(lease).execute.payload[:events]
        log_lease(lease, 'Expanded project authorization refresh events', expanded_events_count: events)
        count(:expanded, lease)
      end

      def compute(lease)
        started_at = ::Gitlab::Metrics::System.monotonic_time
        payload = recalculate(lease).payload

        if payload[:complete]
          RefreshEvent.finish(lease)
        else
          # A project recalculation has no cursor: the next run compares again and skips what this one wrote.
          RefreshEvent.continue(lease, cursor: payload[:cursor])
        end

        log_lease(lease, 'Recalculated project authorization refresh events', complete: payload[:complete],
          Labkit::Fields::DURATION_S => (::Gitlab::Metrics::System.monotonic_time - started_at).round(6),
          rows_added: payload[:written].rows_added, rows_deleted: payload[:written].rows_deleted)
        count(payload[:complete] ? :finished : :continued, lease)
      end

      def recalculate(lease)
        limiter = Gitlab::Metrics::RuntimeLimiter.new(LEASE_LIMIT)

        case lease.target_type
        when :project
          RecalculateProjectService.new(lease.target_id, runtime_limiter: limiter)
        when :user_in_project
          RecalculateUserService.new(lease.target_id, project_ids: [lease.scope_id])
        when :user_in_group
          RecalculateUserService.new(lease.target_id, group_ids: lease.group_ids, cursor: lease.cursor,
            runtime_limiter: limiter)
        when :user
          RecalculateUserService.new(lease.target_id, cursor: lease.cursor, runtime_limiter: limiter)
        else
          raise ArgumentError, "no recalculation for target type #{lease.target_type}"
        end.execute
      end

      # While the group's Sidekiq flag is on, its producers queue their own Sidekiq refresh for every change, so the
      # events are dropped. While it's off, some changes may have no Sidekiq job, so they go to the old workers.
      # Enqueuing comes first, so a failed enqueue retries the events instead of losing them.
      def hand_off_or_drop(lease)
        return drop(lease) unless RefreshEvent.sidekiq_switched_off?(RefreshEvent.group_of(lease.target_type))

        hand_off(lease)
        RefreshEvent.finish(lease)
        log_lease(lease, 'Handed off project authorization refresh events')
        count(:handed_off, lease)
      end

      # The workers directly, not the producers' services, which may skip Sidekiq themselves.
      def hand_off(lease)
        case lease.target_type
        when :project
          AuthorizedProjectUpdate::ProjectRecalculateWorker.perform_async(lease.target_id)
        when :user_in_project
          AuthorizedProjectUpdate::ProjectRecalculatePerUserWorker.perform_async(lease.scope_id, lease.target_id)
        when :user_in_group, :user
          AuthorizedProjectsWorker.perform_async(lease.target_id)
        else
          raise ArgumentError, "no Sidekiq refresh for target type #{lease.target_type}"
        end
      end

      def drop(lease)
        RefreshEvent.finish(lease)
        log_lease(lease, 'Dropped project authorization refresh events')
        count(:dropped, lease)
      end

      def count(outcome, lease)
        counts[outcome][lease.target_type.to_s] += lease.event_ids.size
      end

      def log_lease(lease, message, **extra)
        Gitlab::AppJsonLogger.info(build_structured_payload_labkit(
          Labkit::Fields::LOG_MESSAGE => message,
          target_type: lease.target_type.to_s,
          target_id: lease.target_id,
          scope_id: lease.scope_id,
          events_count: lease.event_ids.size,
          attempts: lease.attempts,
          queued_duration_s: (Time.current - lease.first_queued_at).to_f.round(6),
          **extra
        ))
      end

      # Only what the lease's work unambiguously belongs to: a wrong attribution would mislead throttling
      # decisions more than a missing one. Attribution is best effort, so failing to find it doesn't fail the lease.
      def context_for(lease)
        root_id = root_namespace_id(lease)

        {
          user: (::User.find_by_id(lease.target_id) if USER_TARGET_TYPES.include?(lease.target_type)),
          namespace: (::Namespace.with_route.find_by_id(root_id) if root_id)
        }.compact
      rescue StandardError => e
        Gitlab::ErrorTracking.track_exception(e, target_type: lease.target_type, target_id: lease.target_id)
        {}
      end

      # Nil when the lease spans several roots or none, such as a user's whole access.
      def root_namespace_id(lease)
        namespace_ids = case lease.target_type
                        when :project then ::Project.id_in(lease.target_id).select(:namespace_id)
                        when :user_in_project then ::Project.id_in(lease.scope_id).select(:namespace_id)
                        when :user_in_group then lease.group_ids
                        when :namespace_subtree, :namespace_project_group_links then [lease.target_id]
                        when :group_group_link then [lease.target_id, lease.scope_id]
                        end
        return unless namespace_ids

        roots = ::Namespace.root_ids_for(namespace_ids)
        roots.first if roots.one?
      end

      def response(drained:)
        ServiceResponse.success(payload: counts.transform_keys { |outcome| :"#{outcome}_counts" }
          .merge(drained: drained))
      end
    end
  end
end
