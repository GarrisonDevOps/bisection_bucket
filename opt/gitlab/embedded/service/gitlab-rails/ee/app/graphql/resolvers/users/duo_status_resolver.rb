# frozen_string_literal: true

module Resolvers
  module Users
    class DuoStatusResolver < BaseResolver
      type ::Types::Users::DuoStatusType, null: true

      def self.single
        self
      end

      def resolve(**args)
        return unless object.composite_ai_service_account?

        context[:duo_status_parent] = args[:parent]

        object
      end
    end
  end
end
