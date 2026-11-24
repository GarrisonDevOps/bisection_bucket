# frozen_string_literal: true

module Security
  module BackgroundOperationTracking
    extend ActiveSupport::Concern

    included do
      attr_reader :operation_id, :user
    end

    def self.humanized_operation_type(operation_type)
      _(operation_type.to_s.humanize)
    end

    private

    def operation_exists?
      return true unless operation_id

      Gitlab::BackgroundOperations::RedisStore.get_operation(operation_id).present?
    end

    def record_failure(entity, error_message)
      entity_type = entity.is_a?(Group) ? 'Group' : 'Project'

      Gitlab::BackgroundOperations::RedisStore.add_failed_item(
        operation_id,
        entity_id: entity.id,
        entity_type: entity_type,
        entity_name: entity.name,
        entity_full_path: entity.full_path,
        error_message: error_message
      )
    end

    def record_success(count = 1)
      Gitlab::BackgroundOperations::RedisStore.increment_successful(operation_id, count)
    end

    def finalize_if_complete
      operation = Gitlab::BackgroundOperations::RedisStore.get_operation(operation_id)
      return unless operation
      return unless operation_complete?(operation)

      # The claim is destructive, so a crash before the enqueue below loses the only
      # notification the user gets for this operation: the retry finds nothing left
      # to finalize.
      failed_items = Gitlab::BackgroundOperations::RedisStore.claim_for_finalization(operation_id)
      return unless failed_items

      send_failure_notification(operation, failed_items) if operation.failed_items > 0
    end

    def operation_complete?(operation)
      (operation.successful_items + operation.failed_items) >= operation.total_items
    end

    def send_failure_notification(operation, failed_items)
      operation_data = {
        id: operation.id,
        operation_type: operation.operation_type,
        total_items: operation.total_items,
        successful_items: operation.successful_items,
        failed_items: operation.failed_items
      }

      Security::BackgroundOperationMailer.failure_notification(
        user: user,
        operation: operation_data,
        failed_items: failed_items
      ).deliver_later
    end
  end
end
