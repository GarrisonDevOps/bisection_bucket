# frozen_string_literal: true

module Types
  module Ai
    module Catalog
      class ItemVerificationLevelEnum < BaseEnum
        graphql_name 'AiCatalogItemVerificationLevel'

        ::Ai::Catalog::Item.verification_levels.each_key do |level|
          value level.upcase.to_sym, value: level, description: "The item is #{level.titleize}"
        end
      end
    end
  end
end
