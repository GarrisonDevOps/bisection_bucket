# frozen_string_literal: true

module Types
  module Cd
    class EnvironmentTierEnum < BaseEnum
      graphql_name 'CdEnvironmentTier'
      description 'Tier of a continuous deployment environment.'

      ::Cd::Environment.tiers.each_key do |tier|
        display_name = tier == 'qa' ? 'QA' : tier
        value tier.upcase, value: tier, description: "Environment is in the #{display_name} tier."
      end
    end
  end
end
