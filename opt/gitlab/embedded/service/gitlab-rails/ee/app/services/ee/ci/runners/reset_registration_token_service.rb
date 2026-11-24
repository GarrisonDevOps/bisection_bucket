# frozen_string_literal: true

module EE
  module Ci
    module Runners
      module ResetRegistrationTokenService
        extend ::Gitlab::Utils::Override

        include ::AuditEvents::SafeRunnerToken

        override :execute
        def execute
          previous_registration_token = runners_token

          result = super
          if result.success?
            audit_event(previous_registration_token, result.payload[:new_registration_token])
          end

          result
        end

        private

        def audit_event(previous_registration_token, new_registration_token)
          details = {
            from: safe_author(previous_registration_token),
            to: safe_author(new_registration_token)
          }
          details[:errors] = scope.errors.full_messages if scope.errors.present?

          ::Gitlab::Audit::Auditor.audit(
            name: 'ci_runner_token_reset',
            author: user,
            scope: scope.is_a?(::ApplicationSetting) ? ::Gitlab::Audit::InstanceScope.new : scope,
            target: ::Gitlab::Audit::NullTarget.new,
            additional_details: details,
            message: message)
        end

        def runners_token
          if scope.respond_to?(:runners_registration_token)
            scope.runners_registration_token
          else
            scope.runners_token
          end
        end

        def message
          return 'Reset instance runner registration token' if scope.is_a?(::ApplicationSetting)

          "Reset #{scope.class.name.downcase} runner registration token"
        end
      end
    end
  end
end
