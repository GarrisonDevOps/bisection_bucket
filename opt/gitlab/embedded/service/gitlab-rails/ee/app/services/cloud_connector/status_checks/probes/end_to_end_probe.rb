# frozen_string_literal: true

module CloudConnector
  module StatusChecks
    module Probes
      # Performs a real request using the current user to verify that AI features work.
      class EndToEndProbe < BaseProbe
        extend ::Gitlab::Utils::Override

        validate :check_user_exists
        validate :validate_code_completion_availability

        def initialize(user)
          @user = user
        end

        private

        attr_reader :user

        override :success_message
        def success_message
          _('Authentication with the AI gateway services succeeded.')
        end

        def check_user_exists
          errors.add(:base, 'User not provided') unless user
        end

        def validate_code_completion_availability
          return unless user

          error = ::Gitlab::Llm::AiGateway::CodeSuggestionsClient.new(user).test_completion
          errors.add(:base, failure_text(error)) if error.present?
        end

        def failure_text(error)
          format(_('Authentication with the AI gateway services failed: %{error}'), error: error)
        end
      end
    end
  end
end
