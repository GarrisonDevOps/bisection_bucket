# frozen_string_literal: true

module EE
  module Ci
    module Runners
      module ResetAuthenticationTokenService
        extend ::Gitlab::Utils::Override

        private

        override :forbidden_response
        def forbidden_response
          return super unless runner.gitlab_operated_hosted_runner?

          ServiceResponse.error(
            message: s_('Runners|GitLab manages the authentication token of this hosted runner. ' \
              'To rotate it, contact GitLab Support.'),
            reason: :forbidden
          )
        end

        override :validate_reset
        def validate_reset
          return super unless runner.token_rotation_deadline.present?
          return super if runner.token_rotation_deadline.future?

          ServiceResponse.error(message: s_('Runners|Token rotation deadline has passed'), reason: :forbidden)
        end

        override :reset_runner_token!
        def reset_runner_token!
          runner.token_rotation_deadline = nil

          super
        end
      end
    end
  end
end
