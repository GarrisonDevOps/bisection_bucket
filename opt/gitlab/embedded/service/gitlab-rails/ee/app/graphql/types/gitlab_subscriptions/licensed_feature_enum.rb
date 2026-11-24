# frozen_string_literal: true

module Types
  module GitlabSubscriptions
    class LicensedFeatureEnum < BaseEnum
      graphql_name 'LicensedFeature'
      description 'Licensed features that can be checked for availability on a namespace or project.'

      features = ::GitlabSubscriptions::Features::ALL_FEATURES - ::GitlabSubscriptions::Features::GLOBAL_FEATURES

      features.uniq.each do |feature|
        value feature.to_s.upcase,
          value: feature.to_s,
          description: "#{feature.to_s.humanize} feature."
      end
    end
  end
end
