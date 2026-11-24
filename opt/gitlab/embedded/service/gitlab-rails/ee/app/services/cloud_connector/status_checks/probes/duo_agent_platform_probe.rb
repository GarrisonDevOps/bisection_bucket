# frozen_string_literal: true

module CloudConnector
  module StatusChecks
    module Probes
      class DuoAgentPlatformProbe < BaseProbe
        extend ::Gitlab::Utils::Override
        include Gitlab::Utils::StrongMemoize

        TLS_MISMATCH_ERROR_PATTERN = /(ssl handshake failed|wrong_version_number|tls)/i

        MockFeatureSetting = Struct.new(:self_hosted?)

        validate :verify_request_success

        def initialize(user, deployment:)
          @user = user
          @deployment = deployment
        end

        private

        def host
          if self_hosted?
            Gitlab::DuoWorkflow::Client.self_hosted_url
          else
            Gitlab::DuoWorkflow::Client.cloud_connected_url(user: @user)
          end
        end
        strong_memoize_attr :host

        def result
          ::Ai::DuoWorkflow::DuoWorkflowService::Client.new(
            duo_workflow_service_url: host,
            current_user: @user,
            secure: secure_for_host,
            feature_setting: feature_setting
          ).list_tools
        end

        def secure_for_host
          Gitlab::DuoWorkflow::Client.secure?(feature_setting: feature_setting)
        end

        def feature_setting
          MockFeatureSetting.new(self_hosted?)
        end
        strong_memoize_attr :feature_setting

        def verify_request_success
          response = result
          return if response[:status] == :success

          errors.add(:base, response[:message])
        end

        override :success_message
        def success_message
          if self_hosted?
            format(
              _('The self-hosted GitLab Duo Agent Platform service at %{host} is operational.'),
              host: host
            )
          else
            format(
              _('The cloud-connected GitLab Duo Agent Platform service at %{host} is operational.'),
              host: host
            )
          end
        end

        def failure_message
          message =
            if self_hosted?
              format(_('The self-hosted GitLab Duo Agent Platform service at %{host} is not reachable.'), host: host)
            else
              format(_('The cloud-connected GitLab Duo Agent Platform service at %{host} is not reachable.'),
                host: host)
            end

          return message unless tls_mismatch_error?

          tls_guidance = _(
            'It fails with a TLS mismatch error. ' \
              'If your self-hosted Duo Agent Platform service endpoint does not support TLS, ' \
              'turn off TLS connection to the GitLab Duo Agent Platform service '
          )

          format(
            _("%{message} %{tls_guidance}"),
            tls_guidance: tls_guidance,
            message: message
          )
        end

        def self_hosted?
          @deployment == :self_hosted
        end

        def tls_mismatch_error?
          self_hosted? &&
            secure_for_host &&
            errors.full_messages.any? { |error_message| error_message.match?(TLS_MISMATCH_ERROR_PATTERN) }
        end
      end
    end
  end
end
