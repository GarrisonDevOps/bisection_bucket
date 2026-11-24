# frozen_string_literal: true

module Resolvers
  module Analytics
    module Orbit
      class NamespaceResolver < BaseResolver
        type ::Types::Analytics::Orbit::NamespaceType, null: true

        def resolve
          object
        end
      end
    end
  end
end
