# frozen_string_literal: true

module Ai
  module Conversation
    class CleanupService
      def execute
        setting = ApplicationSetting.current

        Ai::Conversation::Thread.expired(
          setting.duo_chat_expiration_column,
          setting.duo_chat_expiration_days
        ).each_batch do |relation|
          relation.delete_all
        end
      end
    end
  end
end
