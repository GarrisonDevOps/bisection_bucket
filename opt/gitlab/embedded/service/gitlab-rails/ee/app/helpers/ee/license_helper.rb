# frozen_string_literal: true

module EE
  module LicenseHelper
    delegate :general_admin_application_settings_path, to: 'Gitlab::Routing.url_helpers'

    def seats_calculation_message(license)
      return unless license.exclude_guests_from_active_count?

      _("Users with a Guest role or those who don't belong to a Project or Group " \
        "will not use a seat from your license.")
    end

    def has_active_license?
      License.current.present?
    end

    def groups_count
      return if has_active_license?

      groups = ::GroupsFinder.new(current_user, active: true).execute
      groups.count
    end

    def projects_count
      return if has_active_license?

      projects = ::ProjectsFinder.new(current_user: current_user, params: { active: true }).execute
      projects.count
    end

    def users_count
      return if has_active_license?

      users = ::User.filter_items(nil)
      users.count
    end

    def show_promotions?(selected_user = current_user, hide_on_self_managed: false)
      return false unless selected_user

      if ::Gitlab::Saas.feature_available?(:gitlab_com_subscriptions)
        true
      elsif hide_on_self_managed
        false
      else
        license = License.current
        license.nil? || license.expired?
      end
    end

    def licensed_users(license)
      if license.restricted?(:active_user_count)
        number_with_delimiter(license.restrictions[:active_user_count])
      else
        _('Unlimited')
      end
    end

    # EE:Self Managed
    def cloud_license_view_data
      {
        customers_portal_url: subscription_portal_manage_url,
        free_trial_path: new_self_managed_trials_path,
        has_active_license: (has_active_license? ? 'true' : 'false'),
        groups_count: groups_count,
        projects_count: projects_count,
        users_count: users_count,
        license_remove_path: (Ability.allowed?(current_user, :delete_license) ? admin_license_path : ''),
        subscription_sync_path: sync_seat_link_admin_license_path,
        license_usage_file_path: admin_license_usage_export_path(format: :csv),
        is_admin: current_user.can_admin_all_resources?.to_s,
        settings_add_license_path: general_admin_application_settings_path(anchor: 'js-add-license-toggle'),
        purchase_credits_path: subscription_portal_self_managed_purchase_credits_url,
        billable_usage_report_path: billable_usage_report_path_for_view
      }
    end

    # Empty unless the instance can actually produce a report, so the frontend can gate
    # the entry point on the path alone.
    def billable_usage_report_path_for_view
      return '' unless ::Utilization::BillableUsage::Exports::Availability.enabled?

      billable_usage_admin_subscription_path
    end

    # EE:Self Managed
    def billable_usage_report_view_data
      {
        terms_path: terms_admin_license_billable_usage_export_path(format: :json),
        report_path: admin_license_billable_usage_export_path(format: :json),
        download_path: download_admin_license_billable_usage_export_path,
        subscription_path: admin_subscription_path
      }
    end

    extend self
  end
end
