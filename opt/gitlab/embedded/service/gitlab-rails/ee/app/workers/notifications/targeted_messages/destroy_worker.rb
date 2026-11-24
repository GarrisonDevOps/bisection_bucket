# frozen_string_literal: true

module Notifications
  module TargetedMessages
    class DestroyWorker
      include ApplicationWorker

      data_consistency :sticky
      feature_category :acquisition
      idempotent!
      urgency :low
      defer_on_database_health_signal :gitlab_main

      def perform(targeted_message_id)
        targeted_message = Notifications::TargetedMessage.find_by_id(targeted_message_id)
        if targeted_message.nil?
          Gitlab::AppLogger.info("TargetedMessage with ID #{targeted_message_id} not found.")
          return
        end

        delete_associated_records_in_batches(targeted_message)
        targeted_message.destroy!
      end

      private

      def delete_associated_records_in_batches(targeted_message)
        targeted_message.targeted_message_dismissals.each_batch do |batch|
          batch.delete_all
        end

        targeted_message.targeted_message_namespaces.each_batch do |batch|
          batch.delete_all
        end
      end
    end
  end
end
