# frozen_string_literal: true

class Groups::SeatUsageController < Groups::ApplicationController
  before_action :verify_top_level_group
  before_action :authorize_admin_group_member!

  layout "group_settings"

  feature_category :subscription_management
  urgency :low

  def show
    respond_to do |format|
      format.html do
        redirect_to_seat_usage_tab
      end

      format.csv do
        check_seat_usage_export_rate_limit!
        next if performed?

        result = Groups::SeatUsageExportService.execute(group, current_user)

        if result.success?
          stream_csv_headers(csv_filename)

          self.response_body = result.payload
        else
          flash[:alert] = _('Failed to generate export, please try again later.')

          redirect_to_seat_usage_tab
        end
      end
    end
  end

  private

  def check_seat_usage_export_rate_limit!
    scope = ::GitlabSubscriptions::BilledUsersScanRateLimit.rate_limit_scope(current_user, group)
    keys = [:seat_usage_export, *::GitlabSubscriptions::BilledUsersScanRateLimit::RATE_LIMIT_KEYS]

    keys.each do |key|
      check_rate_limit!(key, scope: scope) do
        flash[:alert] = ::Gitlab::ApplicationRateLimiter.throttled_error_message
        redirect_to_seat_usage_tab
      end

      break if performed?
    end
  end

  def redirect_to_seat_usage_tab
    redirect_to group_usage_quotas_path(group, anchor: 'seats-quota-tab')
  end

  def csv_filename
    "seat-usage-export-#{Time.current.to_fs(:number)}.csv"
  end

  def verify_top_level_group
    not_found unless group.root?
  end
end
