# frozen_string_literal: true

module Types
  module Ai
    module FeatureSettings
      class ProvidersEnum < BaseEnum
        graphql_name 'AiFeatureProviders'
        description 'Providers for AI features that can be configured.'

        # this method set the enum values for the allowed features settings.
        def self.set_providers_enum_values
          ::Ai::FeatureSetting.providers.each_key do |provider_key|
            value provider_key.upcase,
              description: "#{provider_key.to_s.humanize.singularize} option",
              value: provider_key
          end
        end

        set_providers_enum_values
      end
    end
  end
end
