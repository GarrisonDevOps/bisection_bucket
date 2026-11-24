# frozen_string_literal: true

module ComplianceManagement
  module Pipl
    class SendRecurringNotificationsWorker
      include ApplicationWorker

      urgency :low
      idempotent!
      deduplicate :until_executing
      data_consistency :sticky
      feature_category :compliance_management
      queue_namespace :cronjob

      def perform
        PiplUser.with_due_notifications.each_batch do |batch|
          batch.each do |pipl_user|
            send_pipl_email(pipl_user.user)
          end
        end
      end

      def send_pipl_email(user)
        ::ComplianceManagement::Pipl::SendRecurringComplianceEmailService.new(user: user).execute
      end
    end
  end
end
