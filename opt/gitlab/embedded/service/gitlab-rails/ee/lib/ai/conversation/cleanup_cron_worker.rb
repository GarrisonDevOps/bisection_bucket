# frozen_string_literal: true

module Ai
  module Conversation
    class CleanupCronWorker
      include ApplicationWorker
      include CronjobQueue # rubocop:disable Scalability/CronWorkerContext -- service does not require context

      idempotent!

      feature_category :chat_engine

      def perform
        Ai::Conversation::CleanupService.new.execute
      end
    end
  end
end
