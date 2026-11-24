# frozen_string_literal: true

module VirtualRegistries
  module Settings
    class CreateOrUpdateService
      ALLOWED_ATTRIBUTES = %i[
        enabled
      ].freeze

      ERRORS = {
        unauthorized: ServiceResponse.error(message: 'Unauthorized', reason: :unauthorized),
        invalid_params: ServiceResponse.error(message: 'Invalid parameters provided', reason: :invalid_params)
      }.freeze

      def initialize(group:, current_user:, params:)
        @group = group
        @current_user = current_user
        @params = params
      end

      def execute
        return ERRORS[:unauthorized] unless allowed?
        return ERRORS[:invalid_params] unless valid_params?

        setting = ::VirtualRegistries::Setting.find_for_group(@group)
        setting.update!(virtual_registries_setting_params)

        ServiceResponse.success(payload: { virtual_registries_setting: setting })
      rescue ActiveRecord::ActiveRecordError => e
        ServiceResponse.error(message: e.message, reason: :persistence_error)
      end

      private

      def allowed?
        Ability.allowed?(@current_user, :update_virtual_registry_setting, @group.virtual_registry_policy_subject)
      end

      def virtual_registries_setting_params
        @params.slice(*ALLOWED_ATTRIBUTES)
      end

      def valid_params?
        @params.present? && (@params.keys & ALLOWED_ATTRIBUTES).any?
      end
    end
  end
end
