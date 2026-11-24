# frozen_string_literal: true

module CloudConnector
  module StatusChecks
    module Probes
      module SelfHosted
        # Performs a real request using the current user to verify that the Self-hosted configuration works.
        class ModelConfigurationProbe
          include ActiveModel::Validations
          include ActiveModel::Validations::Callbacks

          validate :check_user_exists
          validate :check_self_hosted_model_exists
          validate :self_hosted_ai_gateway_configured
          validate :validate_model_connection

          attr_reader :self_hosted_model

          def initialize(user, self_hosted_model)
            @user = user
            @self_hosted_model = self_hosted_model
          end

          def execute
            return failure(failure_message) unless valid?

            success(success_message)
          end

          private

          attr_reader :user

          def success_message
            format(s_('AdminSelfHostedModels|Successfully connected to the self-hosted model'))
          end

          def check_user_exists
            errors.add(:base, _('User not provided')) unless user
          end

          def self_hosted_ai_gateway_configured
            return if self_hosted_ai_gateway_url.present?

            errors.add(:base,
              s_(
                "AdminSelfHostedModels|You have not configured your local AI gateway URL. " \
                  "Configure the URL in the GitLab Duo configuration settings."
              )
            )
          end

          def check_self_hosted_model_exists
            errors.add(:base, s_('AdminSelfHostedModels|Self-hosted model was not provided')) unless self_hosted_model
          end

          def validate_model_connection
            return unless user
            return if self_hosted_model.nil?
            return if self_hosted_ai_gateway_url.blank?

            # An embeddings request needs to be tested through a different route,
            # since it has a different expected payload than other AI models (chat, code completion, etc.)
            error = self_hosted_model.embedding? ? embeddings_request_error : connection_tester_error
            errors.add(:base, failure_text(error)) if error.present?
          end

          def connection_tester_error
            ::Gitlab::Llm::AiGateway::SelfHostedModels::ConnectionTester.new(user, self_hosted_model).execute
          end

          def embeddings_request_error
            result = ::Ai::ActiveContext::TestSelfHostedEmbeddingModelService.new(
              self_hosted_model: self_hosted_model,
              user: user
            ).execute

            result.message unless result.success?
          end

          def failure_text(error)
            format(_('ERROR: %{error}'), error: error)
          end

          def details
            @details ||= ::CloudConnector::StatusChecks::Probes::BaseProbe::Details.new
          end

          def probe_name
            self.class.name.demodulize.underscore.to_sym
          end

          def success(message)
            create_result(true, message)
          end

          def failure(message)
            create_result(false, message)
          end

          def create_result(success, message)
            ::CloudConnector::StatusChecks::Probes::ProbeResult.new(probe_name, success, message, details, errors)
          end

          def failure_message
            errors.full_messages.first
          end

          def self_hosted_ai_gateway_url
            ::Gitlab::AiGateway.self_hosted_url
          end
        end
      end
    end
  end
end
