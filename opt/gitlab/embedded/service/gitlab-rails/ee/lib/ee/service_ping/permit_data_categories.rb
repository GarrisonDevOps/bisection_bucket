# frozen_string_literal: true

module EE
  module ServicePing
    module PermitDataCategories
      extend ::Gitlab::Utils::Override

      STANDARD_CATEGORY = ::ServicePing::PermitDataCategories::STANDARD_CATEGORY
      SUBSCRIPTION_CATEGORY = ::ServicePing::PermitDataCategories::SUBSCRIPTION_CATEGORY
      OPTIONAL_CATEGORY = ::ServicePing::PermitDataCategories::OPTIONAL_CATEGORY
      OPERATIONAL_CATEGORY = ::ServicePing::PermitDataCategories::OPERATIONAL_CATEGORY

      override :execute
      def execute
        optional_enabled = ::Gitlab::CurrentSettings.include_optional_metrics_in_service_ping?

        [STANDARD_CATEGORY, SUBSCRIPTION_CATEGORY, OPERATIONAL_CATEGORY].tap do |categories|
          categories << OPTIONAL_CATEGORY if optional_enabled
        end.to_set
      end
    end
  end
end
