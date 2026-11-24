# frozen_string_literal: true

module ComplianceManagement
  module Pipl
    class UpdateUserCountryAccessLogsService
      include ::Gitlab::Utils::StrongMemoize

      ACCESS_FROM_PIPL_COVERED_COUNTRY_THRESHOLD = 5

      def initialize(user, country_code)
        @user = user
        @country_code = country_code
      end

      def execute
        return unless user
        return unless country_code

        if COVERED_COUNTRY_CODES.include?(country_code)
          accessed_from_pipl_covered_country(country_code)

          UserPaidStatusCheckWorker.perform_async(user.id) if met_pipl_access_threshold?
        else
          accessed_outside_pipl_covered_countries
        end
      end

      private

      attr_reader :user, :country_code

      def accessed_from_pipl_covered_country(country_code)
        return if recently_tracked?

        # User can only have one country_access_log for each unique country
        # code. Access from the same country code reuses an existing record.
        # Further, this service is only executed in a worker and is not wrapped
        # by another transaction.
        log = Users::CountryAccessLog.safe_find_or_create_by(user: user, country_code: country_code) # rubocop:disable Performance/ActiveRecordSubtransactionMethods -- see previous lines

        Users::CountryAccessLog.transaction do
          now = Time.zone.now
          log.lock!
          log.first_access_at = now if log.access_count < 1
          log.last_access_at = now
          log.access_count += 1

          if log.valid?
            log.save
            ComplianceManagement::PiplUser.track_access(user)
          end
        end
      end

      def accessed_outside_pipl_covered_countries
        return unless access_logs.exists?

        Users::CountryAccessLog.transaction do
          access_logs.update_all(access_count_reset_at: Time.zone.now, access_count: 0)
          ComplianceManagement::PiplUser.untrack_access!(user)
        end
      end

      def met_pipl_access_threshold?
        # A user can be subject to PIPL when:
        # - They have exclusively accessed from PIPL-covered countries in the past 6 months; OR
        # - They have exclusively accessed from PIPL-covered countries 5 times or more
        #
        # Notes:
        # 1. Accesses from any PIPL-covered country is counted only once per day.
        # I.e. if the user accessed from CN and HK in the same day only the first
        # access will be counted
        # 2. 'Exclusively' means the user has not accessed from any country other
        # than PIPL-covered countries. Otherwise, _all_ of the user's access log
        # records from PIPL-covered countries are updated to have access_count =
        # 0 and access_count_reset_at = Time.zone.now.

        return false unless access_logs.exists?

        access_logs.first_access_before(6.months.ago).exists? ||
          access_logs.sum(:access_count) >= ACCESS_FROM_PIPL_COVERED_COUNTRY_THRESHOLD
      end

      def access_logs
        user.country_access_logs.from_country_code(COVERED_COUNTRY_CODES).with_access
      end
      strong_memoize_attr :access_logs

      def recently_tracked?
        pipl_user = ComplianceManagement::PiplUser.for_user(user)
        pipl_user&.recently_tracked?
      end
    end
  end
end
