# frozen_string_literal: true

module DependencyProxy
  module Packages
    module Settings
      class UpdateService
        ALLOWED_ATTRIBUTES = %i[
          enabled
          maven_external_registry_url
          maven_external_registry_username
          maven_external_registry_password
        ].freeze

        def initialize(setting:, current_user: nil, params: {})
          @setting = setting
          @current_user = current_user
          @params = params
        end

        def execute
          return ServiceResponse.error(message: 'Access Denied') unless allowed?

          if @setting.update(dependency_proxy_packages_setting_params)
            ServiceResponse.success(payload: { dependency_proxy_packages_setting: @setting })
          else
            ServiceResponse.error(message: @setting.errors.full_messages.to_sentence || 'Bad request')
          end
        end

        private

        def allowed?
          Ability.allowed?(@current_user, :admin_dependency_proxy_packages_settings, @setting)
        end

        def dependency_proxy_packages_setting_params
          @params.slice(*ALLOWED_ATTRIBUTES)
        end
      end
    end
  end
end
