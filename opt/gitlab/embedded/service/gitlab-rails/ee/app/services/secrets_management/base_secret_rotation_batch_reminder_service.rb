# frozen_string_literal: true

module SecretsManagement
  class BaseSecretRotationBatchReminderService
    BATCH_SIZE = 100
    FAILED_REMINDER_DELAY = 1.day

    def initialize
      @processed_count = 0
      @skipped_count = 0
      @notification_service = NotificationService.new
    end

    def execute
      @processed_count = 0
      @skipped_count = 0

      rotation_info_class.pending_reminders
        .limit(BATCH_SIZE)
        .each do |rotation_info|
        process_with_isolation(rotation_info)
      end

      log_completion_stats

      {
        processed_count: processed_count,
        skipped_count: skipped_count
      }
    end

    private

    attr_reader :notification_service, :processed_count, :skipped_count

    def rotation_info_class
      raise Gitlab::AbstractMethodError
    end

    def send_rotation_reminder(_rotation_info)
      raise Gitlab::AbstractMethodError
    end

    # A failed row isn't marked sent, so it would stay first in `pending_reminders`
    # and block every other reminder of this type. Push it back instead.
    def process_with_isolation(rotation_info)
      if orphaned_rotation_record?(rotation_info)
        cleanup_orphaned_record(rotation_info)
        @skipped_count += 1
      else
        process_rotation_reminder(rotation_info)
      end
    rescue StandardError => e
      Gitlab::ErrorTracking.track_exception(
        e,
        rotation_info_class: rotation_info.class.name,
        rotation_info_id: rotation_info.id,
        **parent_log_fields(rotation_info)
      )

      rotation_info.update_column(:next_reminder_at, FAILED_REMINDER_DELAY.from_now)
    end

    def orphaned_rotation_record?(rotation_info)
      resource = rotation_info.resource
      return true unless resource.secrets_manager&.active?

      secret_metadata = secrets_manager_client_for(rotation_info)
        .read_secret_metadata(
          resource.secrets_manager.ci_secrets_mount_path,
          resource.secrets_manager.ci_data_path(rotation_info.secret_name)
        )

      return true if secret_metadata.nil?

      stored_rotation_info_id = secret_metadata.dig("custom_metadata", "secret_rotation_info_id")
      stored_rotation_info_id != rotation_info.id.to_s
    end

    def cleanup_orphaned_record(rotation_info)
      rotation_info.destroy!

      log_orphaned_cleanup(rotation_info)
    end

    def process_rotation_reminder(rotation_info)
      send_rotation_reminder(rotation_info)

      rotation_info.notification_sent!

      @processed_count += 1

      log_processed_secret(rotation_info)
    end

    def log_processed_secret(rotation_info)
      Gitlab::AppLogger.info(
        message: 'Secret rotation reminder processed successfully',
        secret_name: rotation_info.secret_name,
        **parent_log_fields(rotation_info),
        last_reminder_at: rotation_info.last_reminder_at,
        next_reminder_at: rotation_info.next_reminder_at
      )
    end

    def log_orphaned_cleanup(rotation_info)
      Gitlab::AppLogger.info(
        message: 'Cleaned up orphaned secret rotation record',
        secret_name: rotation_info.secret_name,
        **parent_log_fields(rotation_info)
      )
    end

    def parent_log_fields(rotation_info)
      { rotation_info.class.parent_id_column => rotation_info.parent_id }
    end

    def log_completion_stats
      Gitlab::AppLogger.info(
        message: 'Secret rotation batch reminder service completed',
        processed_count: processed_count,
        skipped_count: skipped_count
      )
    end
  end
end
