# frozen_string_literal: true

module Admin
  module Ai
    class AmazonQSettingsController < Admin::ApplicationController
      feature_category :ai_abstraction_layer

      before_action :check_can_admin_amazon_q
      before_action :expire_current_settings

      def index
        setup_view_model
      end

      def create
        service = if ::Ai::Setting.for_organization_read_only(::Current.organization).amazon_q_ready
                    ::Ai::AmazonQ::UpdateService
                  else
                    ::Ai::AmazonQ::CreateService
                  end

        response = service.new(current_user, permitted_params).execute

        message = if response.success?
                    { notice: s_('AmazonQ|Amazon Q Settings have been saved.') }
                  else
                    { alert: response.message.presence || s_("AmazonQ|Something went wrong saving Amazon Q settings.") }
                  end

        redirect_to(
          edit_admin_application_settings_integration_path(:amazon_q),
          **message
        )
      end

      def disconnect
        return head :unprocessable_entity unless ::Ai::AmazonQ.connected?

        response = ::Ai::AmazonQ::DestroyService.new(current_user).execute

        if response.success?
          head :ok
        else
          uuid_mismatch = response.message&.include?(::Ai::AmazonQ::BaseService::UUID_MISMATCH_ERROR_MESSAGE)
          error_type = uuid_mismatch ? 'uuid_mismatch' : 'generic'
          render json: { message: response.message, error_type: error_type }, status: :unprocessable_entity
        end
      end

      private

      def setup_view_model
        @view_model = {
          submitUrl: admin_ai_amazon_q_settings_path,
          disconnectUrl: disconnect_admin_ai_amazon_q_settings_path,
          identityProviderPayload: identity_provider,
          amazonQSettings: {
            ready: ::Ai::Setting.for_organization_read_only(::Current.organization).amazon_q_ready,
            roleArn: ::Ai::Setting.for_organization_read_only(::Current.organization).amazon_q_role_arn,
            availability: Gitlab::CurrentSettings.duo_availability
          }
        }
      end

      def identity_provider
        result = ::Ai::AmazonQ::IdentityProviderPayloadFactory.new.execute

        case result
        in { ok: payload }
          payload
        in { err: err }
          flash[:alert] = [
            s_('AmazonQ|Something went wrong retrieving the identity provider payload.'),
            err[:message]
          ].reject(&:blank?).join(' ')

          {}
        end
      end

      def check_can_admin_amazon_q
        render_404 unless ::Ai::AmazonQ.feature_available?
      end

      def expire_current_settings
        # clear cached settings  so that duo_availability shows up correctly
        Gitlab::CurrentSettings.expire_current_application_settings
      end

      def permitted_params
        params
          .permit(:role_arn, :availability, :auto_review_enabled)
          .merge(organization_id: admin_current_organization.id)
      end
    end
  end
end
