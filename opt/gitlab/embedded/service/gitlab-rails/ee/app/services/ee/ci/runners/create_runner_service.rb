# frozen_string_literal: true

module EE
  module Ci
    module Runners
      # Creates a CI Runner and logs an audit event
      module CreateRunnerService
        extend ::Gitlab::Utils::Override

        MINIMUM_TOKEN_EXPIRY_DURATION = 5.minutes
        MAXIMUM_TOKEN_EXPIRY_DURATION = 21.days

        override :execute
        def execute
          super.tap do |response|
            audit_event(response.payload[:runner]) if response.success?
          end
        end

        override :extra_tracking_properties
        def extra_tracking_properties(runner)
          {}.tap do |props|
            props[:has_token_expiration] = 'true' if runner.explicit_token_expires_at.present?
            props[:has_rotation_deadline] = 'true' if runner.token_rotation_deadline.present?
          end
        end

        override :normalize_token_expiration_params
        def normalize_token_expiration_params
          expires_at = params.delete(:token_expires_at)
          params[:explicit_token_expires_at] = expires_at if expires_at

          rotation_deadline = params.delete(:token_rotation_deadline)
          params[:token_rotation_deadline] = rotation_deadline if rotation_deadline
        end

        override :validate_token_expiration_params
        def validate_token_expiration_params(runner)
          expires_at = runner.explicit_token_expires_at

          if params[:token_rotation_deadline] && !expires_at
            return log_token_expiration_validation_failure(
              s_('Runners|token_expires_at is required when token_rotation_deadline is specified'),
              runner
            )
          end

          return unless expires_at

          unless expires_at.acts_like?(:time)
            return log_token_expiration_validation_failure(
              s_('Runners|token_expires_at must be a valid time'),
              runner
            )
          end

          min_expiry = MINIMUM_TOKEN_EXPIRY_DURATION.from_now
          if expires_at < min_expiry
            return log_token_expiration_validation_failure(
              format(
                s_('Runners|token_expires_at must be at least %{minimum} in the future'),
                minimum: MINIMUM_TOKEN_EXPIRY_DURATION.inspect
              ),
              runner
            )
          end

          effective_max = [MAXIMUM_TOKEN_EXPIRY_DURATION.from_now,
            runner.compute_token_expiration(use_explicit: false)].compact.min

          if expires_at > effective_max
            return log_token_expiration_validation_failure(
              format(
                s_('Runners|token_expires_at is too far in the future (maximum is %{maximum})'),
                maximum: effective_max.iso8601
              ),
              runner
            )
          end

          validate_token_rotation_deadline(expires_at, runner)
        end

        private

        def audit_event(runner)
          token_scope = runner.instance_type? ? ::Gitlab::Audit::InstanceScope.new : scope

          ::AuditEvents::RunnerAuditEventService.new(
            runner, user, token_scope,
            name: 'ci_runner_created',
            message: 'Created %{runner_type} CI runner'
          ).track_event
        end

        override :create_hosted_runner!
        def create_hosted_runner!(runner, should_mark_hosted)
          return unless should_create_hosted_runner?(runner, should_mark_hosted)

          ::Ci::HostedRunner.create!(runner_id: runner.id)
        end

        def should_create_hosted_runner?(runner, should_mark_hosted)
          ::Gitlab::Dedicated.feature_available?(:hosted_runners) &&
            should_mark_hosted == true &&
            runner.instance_type?
        end

        def validate_token_rotation_deadline(expires_at, runner)
          deadline = params[:token_rotation_deadline]
          return unless deadline

          unless deadline.acts_like?(:time)
            return log_token_expiration_validation_failure(
              s_('Runners|token_rotation_deadline must be a valid time'),
              runner
            )
          end

          if deadline.past?
            return log_token_expiration_validation_failure(
              s_('Runners|token_rotation_deadline cannot be in the past'),
              runner
            )
          end

          return unless deadline > expires_at

          log_token_expiration_validation_failure(
            s_('Runners|token_rotation_deadline must be less than or equal to token_expires_at'),
            runner
          )
        end

        def log_token_expiration_validation_failure(message, runner)
          ::Gitlab::AppLogger.info(
            message: 'Token expiration validation failed',
            error_message: message,
            class: self.class.name,
            Labkit::Fields::GL_USER_ID => user&.id,
            runner_type: runner.runner_type
          )

          message
        end
      end
    end
  end
end
