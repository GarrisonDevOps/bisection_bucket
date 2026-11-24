# frozen_string_literal: true

module ComplianceManagement
  module Pipl
    class TrackUserCountryAccessService
      include ::Gitlab::Utils::StrongMemoize

      def initialize(user, country_code)
        @user = user
        @country_code = country_code
      end

      def execute
        return unless user
        return unless country_code
        return unless ::Gitlab::Saas.feature_available?(:pipl_compliance)

        access_from_pipl_country = COVERED_COUNTRY_CODES.include?(country_code)

        # If access is from non PIPL-covered country and previous access was not
        # from from a PIPL-covered country (either the user never accessed from
        # PIPL-covered country or their access logs have been reset), there is
        # nothing to do to the user nor their country_access_log records
        return unless access_from_pipl_country || last_pipl_access

        return if access_from_pipl_country && last_pipl_access&.recently_tracked?

        UpdateUserCountryAccessLogsWorker.perform_async(user.id, country_code)
      end

      private

      attr_reader :user, :country_code

      def last_pipl_access
        ComplianceManagement::PiplUser.for_user(user)
      end
      strong_memoize_attr :last_pipl_access
    end
  end
end
