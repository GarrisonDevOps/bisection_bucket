# frozen_string_literal: true

module GitlabSubscriptions
  class UploadLicenseService
    def initialize(params, path_to_subscription_page)
      @params = params
      @license = License.new(params)
      @path_to_subscription_page = path_to_subscription_page
    end

    def execute
      return error_response(license_file_error) if license_file_missing?
      return error_response(online_license_error) if license.online_cloud_license?

      if license.save
        update_add_on_purchases

        ServiceResponse.success(payload: { license: license }, message: success_message)
      else
        error_response(license.errors.full_messages.join.html_safe, license: license) # rubocop:disable Rails/OutputSafety -- Calling html_safe should be fine here
      end
    end

    private

    attr_reader :params, :license, :path_to_subscription_page

    def license_file_missing?
      params[:data].blank? && params[:data_file].blank?
    end

    def license_file_error
      format(
        _('The license you uploaded is invalid. If the issue persists, contact support at %{link}.'),
        link: '<a href="https://support.gitlab.com">https://support.gitlab.com</a>'.html_safe
      ).html_safe # rubocop:disable Rails/OutputSafety -- Calling html_safe is safe here
    end

    def online_license_error
      format(
        _(
          "It looks like you're attempting to activate your subscription. Use " \
            "%{a_start}the Subscription page%{a_end} instead."
        ),
        a_start: "<a href=\"#{path_to_subscription_page}\">".html_safe, # rubocop:disable Rails/OutputSafety -- Calling html_safe is safe here
        a_end: '</a>'.html_safe
      ).html_safe # rubocop:disable Rails/OutputSafety -- Calling html_safe is safe here
    end

    def error_response(message, license: License.new)
      ServiceResponse.error(payload: { license: license }, message: message)
    end

    def success_message
      if license.started?
        _('The license was successfully uploaded and is now active. You can see the details below.')
      else
        format(
          _(
            'The license was successfully uploaded and will be active from %{starts_at}. ' \
              'You can see the details below.'
          ),
          starts_at: license.starts_at
        )
      end
    end

    def update_add_on_purchases
      provision_service = if license.offline_cloud_license?
                            ::GitlabSubscriptions::AddOnPurchases::SelfManaged::ProvisionServices::AddOns
                          else
                            ::GitlabSubscriptions::AddOnPurchases::SelfManaged::ProvisionServices::OrbitPromo
                          end

      provision_service.new.execute
    end
  end
end
