# frozen_string_literal: true

module EE
  module GraphqlChannel
    extend ActiveSupport::Concern

    prepended do
      private

      def authorization_scopes
        super + [:ai_features]
      end
    end
  end
end
