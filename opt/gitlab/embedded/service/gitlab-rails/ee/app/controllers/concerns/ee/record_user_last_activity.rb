# frozen_string_literal: true

module EE
  module RecordUserLastActivity
    extend ActiveSupport::Concern
    extend ::Gitlab::Utils::Override

    override :set_user_last_activity
    def set_user_last_activity
      super

      country_code = request.env['HTTP_CF_IPCOUNTRY']
      ComplianceManagement::Pipl::TrackUserCountryAccessService.new(current_user, country_code).execute
    end
  end
end
