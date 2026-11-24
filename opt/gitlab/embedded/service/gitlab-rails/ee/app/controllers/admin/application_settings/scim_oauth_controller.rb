# frozen_string_literal: true

module Admin
  module ApplicationSettings
    class ScimOauthController < Admin::ApplicationController
      feature_category :user_management
      before_action :check_feature_available
      before_action :check_instance_saml_provider_enabled!, unless: :existing_scim_token?

      def create
        scim_token = ScimOauthAccessToken.first ||
          ScimOauthAccessToken.new(organization_id: admin_current_organization.id)

        if scim_token.new_record?
          scim_token.save
        else
          scim_token.reset_token!
        end

        respond_to do |format|
          format.json do
            if scim_token.errors.empty?
              render json: scim_token.as_entity_json
            else
              render json: { errors: scim_token.errors.full_messages }, status: :unprocessable_entity
            end
          end
        end
      end

      private

      def check_feature_available
        render_404 unless License.feature_available?(:instance_level_scim)
      end

      def check_instance_saml_provider_enabled!
        render_404 unless ::Gitlab::Auth::Saml::Config.enabled?
      end

      def existing_scim_token?
        ScimOauthAccessToken.exists?
      end
    end
  end
end
