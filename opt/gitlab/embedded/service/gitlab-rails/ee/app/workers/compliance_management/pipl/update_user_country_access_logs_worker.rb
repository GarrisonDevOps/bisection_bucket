# frozen_string_literal: true

module ComplianceManagement
  module Pipl
    class UpdateUserCountryAccessLogsWorker
      include ApplicationWorker

      data_consistency :delayed
      deduplicate :until_executed
      idempotent!
      feature_category :instance_resiliency
      urgency :low

      def perform(user_id, country_code)
        return unless country_code

        @user = User.find_by_id(user_id)

        return unless user

        UpdateUserCountryAccessLogsService.new(user, country_code).execute
      end

      private

      attr_reader :user
    end
  end
end
