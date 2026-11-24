# frozen_string_literal: true

module CloudConnector
  module StatusChecks
    module Probes
      class LicenseProbe < BaseProbe
        extend ::Gitlab::Utils::Override

        validate :check_license_exists
        validate :check_license_valid

        after_validation :collect_instance_details, :collect_license_details

        private

        def license
          @license ||= License.current
        end

        override :success_message
        def success_message
          _('Subscription can be synchronized.')
        end

        def check_license_exists
          errors.add(:base, missing_license_text) unless license
        end

        def check_license_valid
          return unless license
          return if license.online_cloud_license?

          errors.add(:base, wrong_license_text)
        end

        def collect_instance_details
          details.add(:instance_id, Gitlab::GlobalAnonymousId.instance_id)
          details.add(:gitlab_version, Gitlab::VERSION)
        end

        def collect_license_details
          return unless license

          details.add(:license, license.license.as_json)
        end

        def missing_license_text
          _("Subscription for this instance cannot be synchronized. " \
            "Contact GitLab customer support to obtain a license.")
        end

        def wrong_license_text
          _("Subscription for this instance cannot be synchronized. " \
            "Contact GitLab customer support to upgrade your license.")
        end
      end
    end
  end
end
