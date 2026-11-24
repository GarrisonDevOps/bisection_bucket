# frozen_string_literal: true

module LicenseMonitoringHelper
  include Gitlab::Utils::StrongMemoize

  def users_over_license
    license_overage_available? ? current_license_overage : 0
  end
  strong_memoize_attr :users_over_license

  private

  def license_overage_available?
    return if ::Gitlab.com?
    return if current_license.nil?

    current_license_overage > 0
  end

  def current_license
    License.current
  end
  strong_memoize_attr :current_license

  def current_license_overage
    current_license.overage_with_historical_max
  end
  strong_memoize_attr :current_license_overage

  def total_user_count
    current_license.seats
  end
  strong_memoize_attr :total_user_count

  def remaining_user_count
    current_license.remaining_user_count
  end
  strong_memoize_attr :remaining_user_count
end
