# frozen_string_literal: true

module Resolvers
  module Geo
    class AchievementUploadRegistriesResolver < BaseResolver
      type ::Types::Geo::GeoNodeType.connection_type, null: true

      include RegistriesResolver
    end
  end
end
