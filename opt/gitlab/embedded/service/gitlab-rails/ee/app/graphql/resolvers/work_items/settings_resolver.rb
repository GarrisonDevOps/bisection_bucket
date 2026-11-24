# frozen_string_literal: true

module Resolvers
  module WorkItems
    class SettingsResolver < BaseResolver
      type ::Types::WorkItems::SettingsType, null: true

      def resolve
        ::WorkItems::Settings.for_namespace(object)
      end
    end
  end
end
