# frozen_string_literal: true

module Ci
  module Runners
    class ResetAuthenticationTokenService
      attr_reader :runner, :current_user, :source

      PERMITTED_SOURCES = %i[runner_api].freeze

      def initialize(runner:, current_user: nil, source: nil)
        @runner = runner
        @current_user = current_user
        @source = source
      end

      def execute
        return forbidden_response unless reset_permitted?

        validation_response = validate_reset
        return validation_response if validation_response.error?

        reset_runner_token!

        ServiceResponse.success
      rescue ActiveRecord::RecordInvalid => e
        ServiceResponse.error(message: e.message, reason: :unprocessable_entity)
      end

      private

      def reset_permitted?
        @source&.in?(PERMITTED_SOURCES) || Ability.allowed?(current_user, :reset_runner_authentication_token, runner)
      end

      # Overridden in EE to explain refusals on GitLab-managed runners
      def forbidden_response
        ServiceResponse.error(message: 'Not permitted to reset', reason: :forbidden)
      end

      # Overridden in EE to validate token rotation deadline
      def validate_reset
        ServiceResponse.success
      end

      # Overridden in EE to clear token rotation deadline before reset
      def reset_runner_token!
        runner.reset_token!
      end
    end
  end
end

Ci::Runners::ResetAuthenticationTokenService.prepend_mod
