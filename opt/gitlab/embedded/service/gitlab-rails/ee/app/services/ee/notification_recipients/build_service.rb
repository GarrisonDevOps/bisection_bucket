# frozen_string_literal: true

#
# Used by NotificationService to determine who should receive notification
#
module EE
  module NotificationRecipients # rubocop:disable Gitlab/BoundedContexts -- Existing module structure
    module BuildService
      # @return [Array<NotificationRecipient>] users who opted in to this service account pipeline event
      def self.build_service_account_recipients(...)
        ::NotificationRecipients::Builder::ServiceAccount.new(...).notification_recipients
      end
    end
  end
end
