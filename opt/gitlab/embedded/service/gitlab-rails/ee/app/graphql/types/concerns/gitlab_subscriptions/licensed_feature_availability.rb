# frozen_string_literal: true

module GitlabSubscriptions
  module LicensedFeatureAvailability
    def licensed_feature_availability(feature:)
      feature_sym = feature.to_sym

      available = object.licensed_feature_available?(feature_sym)
      required_plan = ::GitlabSubscriptions::Features.plans_with_feature(feature_sym).first

      { available: available, required_plan: required_plan }
    end
  end
end
