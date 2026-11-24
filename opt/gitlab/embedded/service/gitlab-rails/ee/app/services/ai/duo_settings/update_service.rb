# frozen_string_literal: true

module Ai
  module DuoSettings
    class UpdateService
      include Gitlab::InternalEvents::ServiceTracking

      track_internal_event 'require_sandbox_setting_changed',
        on: ->(result) { result.success? && result.payload.saved_change_to_require_sandbox? },
        additional_properties: ->(result) { { label: 'instance', value: result.payload.require_sandbox ? 1 : 0 } }

      # Per-cell infrastructure settings stored on ApplicationSetting. All the
      # other params are organization-scoped and stored on Ai::Setting.
      INSTANCE_LEVEL_PARAMS = %i[
        ai_gateway_url
        ai_gateway_timeout_seconds
        duo_agent_platform_service_url
        self_hosted_duo_agent_platform_service_secure
      ].freeze

      def initialize(update_params, current_user: nil)
        @params = update_params
        @current_user = current_user
      end

      def execute
        unless current_user&.can_admin_all_resources?
          return ServiceResponse.error(message: _("Unable to update AI settings"))
        end

        # Admin-area request context: the organization is assigned by the request middleware.
        ai_settings = ::Ai::Setting.for_organization(::Current.organization) # rubocop:disable Gitlab/AvoidCurrentOrganization -- see request-context note above
        application_settings = ::Gitlab::CurrentSettings.current_application_settings

        instance_params = params.slice(*INSTANCE_LEVEL_PARAMS)
        organization_params = params.except(*INSTANCE_LEVEL_PARAMS)

        ::ApplicationRecord.transaction do
          application_settings.update!(instance_params) if instance_params.present?
          ai_settings.update!(organization_params) if organization_params.present?
        end

        Ai::DuoSettings::ChangesAuditor.new(current_user, ai_settings).execute
        Ai::DuoSettings::ChangesAuditor.new(current_user, application_settings).execute if instance_params.present?

        ServiceResponse.success(payload: ai_settings)
      rescue ActiveRecord::RecordInvalid => e
        message = e.record.errors.full_messages.join(", ")

        # The failed (and rolled back) update can leave dirty attribute values
        # on the request-cached settings records; reset them so subsequent
        # reads in the same request return the persisted values.
        ai_settings.reset
        application_settings.reset

        ServiceResponse.error(message: message)
      rescue StandardError => e
        Gitlab::ErrorTracking.track_exception(e)
        ServiceResponse.error(message: _("Unable to update AI settings"))
      end

      private

      attr_reader :params, :current_user
    end
  end
end
