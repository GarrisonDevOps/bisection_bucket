# frozen_string_literal: true

module CloudConnector
  module StatusChecks
    module Probes
      module AmazonQ
        # Performs a connectivity check request to Amazon Q to verify that
        # GitLab can perform requests to Amazon Q and Amazon Q can perform API requests
        # back to the GitLab instance.
        class EndToEndProbe < BaseProbe
          extend ::Gitlab::Utils::Override

          STATUS_CODE_PASSED = "PASSED"
          STATUS_CODE_FAILED = "FAILED"

          validate :check_user_exists

          def initialize(user)
            @user = user
          end

          def execute
            return failure(failure_message) unless valid?

            verify_oauth_app_probe_results
          end

          private

          attr_reader :user

          def check_user_exists
            errors.add(:base, _('User not provided')) unless user
          end

          def verify_oauth_app_probe_results
            return unless user

            response = ::Gitlab::Llm::QAi::Client.new(user).test_connection
            body = response.parsed_response

            unless response.success?
              message = body&.dig('detail') || _('Unknown error')
              error_msg = format(_("Amazon Q connectivity check failed: %{message}"), message: message)
              return [create_result(false, error_msg)]
            end

            probe_results(body)
          end

          def probe_results(body)
            success_status_messages = {
              "GITLAB_INSTANCE_REACHABILITY" =>
                _("Amazon Q successfully received the callback request from your GitLab instance."),
              "GITLAB_CREDENTIAL_VALIDITY" => _("Credentials stored in Amazon Q are valid and functioning correctly.")
            }

            error_status_messages = {
              "GITLAB_INSTANCE_REACHABILITY" =>
                _("Amazon Q could not call your GitLab instance. Please review your configuration and try again. " \
                  "Detail: %{error}"),
              "GITLAB_CREDENTIAL_VALIDITY" =>
                _("The GitLab instance can be reached but the credentials " \
                  "stored in Amazon Q are not valid. Please disconnect and " \
                  "start over.")
            }

            body.filter_map do |check_code, results|
              message = success_status_messages[check_code]
              next if message.blank?

              case results['status']
              when STATUS_CODE_PASSED
                create_result(true, message)
              when STATUS_CODE_FAILED
                message = error_status_messages[check_code]
                error_msg = if message.include?("%{error}")
                              format(message, error: results['message'])
                            else
                              message
                            end

                create_result(false, error_msg)
              end
            end
          end
        end
      end
    end
  end
end
