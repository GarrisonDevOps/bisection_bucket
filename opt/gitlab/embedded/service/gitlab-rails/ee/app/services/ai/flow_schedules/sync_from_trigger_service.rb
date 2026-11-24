# frozen_string_literal: true

module Ai
  module FlowSchedules
    # Synchronizes Ai::FlowSchedule records from a flow trigger's filter JSON.
    #
    # When a flow trigger includes event_type :scheduled (9) and has schedule
    # config in filter["scheduled"], this service creates or updates the
    # corresponding FlowSchedule. When the scheduled event type is removed,
    # it destroys any existing schedules.
    #
    # Called after every trigger write path: FlowTriggers::CreateService and
    # UpdateService, and Catalog::ItemConsumers::CreateService (which creates
    # triggers via nested attributes). Gates creation on the ai_flow_schedules
    # feature flag; teardown runs regardless. Tolerates a nil trigger so callers
    # need no guards.
    class SyncFromTriggerService
      include ::Gitlab::ExclusiveLeaseHelpers

      SCHEDULE_FILTER_KEY = 'scheduled'
      LOCK_TTL = 10.seconds
      LOCK_RETRIES = 2
      LOCK_SLEEP = 0.1.seconds

      def initialize(trigger:)
        @trigger = trigger
      end

      def execute
        return ServiceResponse.success unless @trigger
        return remove_stale_schedules unless Feature.enabled?(:ai_flow_schedules, @trigger.project)

        # Serializes concurrent syncs for the same trigger,
        # preventing two near-simultaneous writes from both seeing
        # no existing schedule and each creating a duplicate.
        in_lock(lock_key, ttl: LOCK_TTL, retries: LOCK_RETRIES, sleep_sec: LOCK_SLEEP) do
          if has_scheduled_event_type? && schedule_config.present?
            upsert_schedule
          elsif !has_scheduled_event_type?
            remove_schedules
          else
            ServiceResponse.success
          end
        end
      rescue Gitlab::ExclusiveLeaseHelpers::FailedToObtainLockError
        ServiceResponse.error(message: 'Could not acquire lock to sync flow schedule')
      end

      private

      def lock_key
        "ai_flow_schedules:sync_from_trigger:#{@trigger.id}"
      end

      def has_scheduled_event_type?
        @trigger.scheduled?
      end

      def schedule_config
        @trigger.filter&.dig(SCHEDULE_FILTER_KEY)
      end

      def upsert_schedule
        conversion = CronConverterService.new(schedule_config).execute
        return conversion if conversion.error?

        schedule = @trigger.flow_schedules.first

        return ServiceResponse.success if schedule.nil? && !scheduled_triggers_available?

        schedule ||= build_schedule
        schedule.cron = conversion.payload[:cron]
        schedule.cron_timezone = conversion.payload[:cron_timezone]
        schedule.active = true if schedule.deactivated_by_failures? && trigger_active?

        return ServiceResponse.error(message: schedule.errors.full_messages.to_sentence) unless schedule.save

        ServiceResponse.success(payload: { flow_schedule: schedule })
      end

      def scheduled_triggers_available?
        return false unless @trigger.scheduled_triggers_beta_available?

        project = @trigger.project

        project.blank? || project.duo_scheduled_triggers_enabled
      end

      def trigger_active?
        ::Ai::FlowTrigger.id_in(@trigger.id).pick(:active)
      end

      def build_schedule
        @trigger.flow_schedules.build(
          project: @trigger.project,
          description: @trigger.description,
          active: true
        )
      end

      def remove_stale_schedules
        return ServiceResponse.success if @trigger.previously_new_record? || has_scheduled_event_type?

        remove_schedules
      end

      def remove_schedules
        @trigger.flow_schedules.destroy_all # rubocop:disable Cop/DestroyAll -- small bounded set (plan-limited)
        ServiceResponse.success
      end
    end
  end
end
