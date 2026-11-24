# frozen_string_literal: true

module Ai
  module AmazonQ
    class BaseService
      include Gitlab::Utils::StrongMemoize

      UUID_MISMATCH_ERROR_MESSAGE = "GitLab instance UUID does not match the registered Identity Provider UUID in AWS"

      def initialize(user, params = {})
        @user = user
        @params = params
      end

      private

      attr_accessor :user, :params

      def availability_param_error
        return ServiceResponse.error(message: 'Missing availability parameter') unless params[:availability].present?

        availability_options = Integrations::AmazonQ::AVAILABILITY_OPTIONS
        return if availability_options.include?(params[:availability])

        ServiceResponse.error(message: "availability must be one of: #{availability_options.join(', ')}")
      end
      strong_memoize_attr :availability_param_error

      def application_settings
        ::Gitlab::CurrentSettings.current_application_settings
      end
      strong_memoize_attr :application_settings

      def ai_settings
        # Admin-area request context: the organization is assigned by the
        # request middleware.
        Ai::Setting.for_organization(::Current.organization) # rubocop:disable Gitlab/AvoidCurrentOrganization -- see request-context note above
      end
      strong_memoize_attr :ai_settings

      def create_audit_event(audit_availability:, audit_ai_settings:, exclude_columns: [])
        message = 'Changed '
        message += "availability to #{application_settings.duo_availability}, " if audit_availability

        if audit_ai_settings
          columns = %w[amazon_q_role_arn amazon_q_service_account_user_id amazon_q_oauth_application_id amazon_q_ready]
          columns -= exclude_columns
          message += columns.map do |column|
            "#{column} to #{ai_settings[column].presence || 'null'}, "
          end.join
        end

        ::Gitlab::Audit::Auditor.audit({
          name: 'q_onbarding_updated',
          author: user,
          scope: Gitlab::Audit::InstanceScope.new,
          target: ai_settings,
          message: message[0...-2]
        })
      end

      def update_integration(params)
        integration = Integration.find_or_initialize_non_project_specific_integration(
          'amazon_q',
          instance: true,
          organization_id: params[:organization_id]
        )

        unless integration
          ai_settings.errors.add(:base,
            "Failed to create an integration: Amazon Q is not available")

          return false
        end

        if integration.update(active: true, **params)
          PropagateIntegrationWorker.perform_async(integration.id)
        else
          ai_settings.errors.add(:base,
            "Failed to create an integration: Error #{integration.errors.full_messages.to_sentence}")
        end

        integration.persisted?
      end
    end
  end
end
