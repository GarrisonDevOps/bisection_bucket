# frozen_string_literal: true

module Types
  module Ai
    module Catalog
      class VersionBumpEnum < BaseEnum
        graphql_name 'AiCatalogVersionBump'
        description 'Possible version bumps for AI catalog items.'

        ::Ai::Catalog::ItemVersion::VERSION_BUMP_OPTIONS.each do |version_bump|
          value version_bump.upcase, description: "#{version_bump.to_s.capitalize} version bump.", value: version_bump
        end
      end
    end
  end
end
