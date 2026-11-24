# frozen_string_literal: true

module VirtualRegistries
  module Cleanup
    class ExecutePolicyWorker
      include ApplicationWorker
      include CronjobChildWorker
      include LimitedCapacity::Worker
      include Gitlab::Utils::StrongMemoize

      MAX_CAPACITY = 2
      POLICY_KLASS = ::VirtualRegistries::Cleanup::Policy
      USER_COLUMNS = %i[id name notification_email email].freeze

      data_consistency :sticky
      feature_category :virtual_registry
      urgency :low
      idempotent!
      defer_on_database_health_signal :gitlab_main, [:virtual_registries_cleanup_policies], 10.minutes

      def perform_work
        return unless policy

        result = ::VirtualRegistries::Cleanup::ExecutePolicyService.new(policy).execute

        if result.success?
          success_attributes(result.payload).tap do |attributes|
            policy.assign_attributes(attributes)
            log_extra_metadata_on_done(:deleted_entries_count, attributes[:last_run_deleted_entries_count])
            log_extra_metadata_on_done(:deleted_size, attributes[:last_run_deleted_size])
          end
        else
          policy.assign_attributes(failure_attributes(result[:message]))
        end

        policy.last_run_at = Time.current
        policy.schedule_next_run!

        notify_group_owners(policy)
      end

      def remaining_work_count
        POLICY_KLASS
          .runnable_schedules
          .limit(max_running_jobs + 1)
          .size
      end

      def max_running_jobs
        MAX_CAPACITY
      end

      private

      def policy
        POLICY_KLASS.transaction do
          to_run = POLICY_KLASS.next_runnable_schedule

          if to_run
            to_run.update_column(:status, :running)
            log_running_policy(to_run)
          end

          to_run
        end
      end
      strong_memoize_attr :policy

      def log_running_policy(policy)
        logger.info(
          structured_payload(
            virtual_registry_cleanup_policy_id: policy.id,
            group_id: policy.group_id
          )
        )
      end

      def success_attributes(payload)
        {
          status: :scheduled,
          failure_message: nil,
          last_run_detailed_metrics: payload,
          last_run_deleted_entries_count: payload.values.sum { |h| h[:deleted_entries_count] },
          last_run_deleted_size: payload.values.sum { |h| h[:deleted_size] }
        }
      end

      def failure_attributes(message)
        {
          status: :failed,
          failure_message: message.truncate(POLICY_KLASS::FAILURE_MESSAGE_MAX_LENGTH)
        }
      end

      def notify_group_owners(policy)
        case policy.attributes.symbolize_keys
        in { status: 'scheduled', notify_on_success: true }
          policy.group.owners.select(*USER_COLUMNS).each do |owner|
            ::Notify.virtual_registry_cleanup_complete(policy, owner).deliver_later
          end
        in { status: 'failed', notify_on_failure: true }
          policy.group.owners.select(*USER_COLUMNS).each do |owner|
            ::Notify.virtual_registry_cleanup_failure(policy, owner).deliver_later
          end
        else
          nil
        end
      end
    end
  end
end
