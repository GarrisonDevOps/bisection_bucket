# frozen_string_literal: true

module VirtualRegistries
  module Container
    class UpdateRegistryService < ::VirtualRegistries::BaseService
      ALLOWED_PARAMS = [:name, :description].freeze
      ERRORS = {
        unauthorized: ServiceResponse.error(message: 'Unauthorized', reason: :unauthorized),
        invalid_params: ServiceResponse.error(message: 'Invalid parameters provided', reason: :invalid_params)
      }.freeze

      def execute
        return ERRORS[:unauthorized] unless allowed?
        return ERRORS[:invalid_params] unless valid_params?

        if registry.update(registry_params)
          ServiceResponse.success(payload: registry)
        else
          ServiceResponse.error(message: registry.errors.full_messages)
        end
      end

      private

      def allowed?
        can?(current_user, :update_virtual_registry, registry)
      end

      def valid_params?
        params.present? && (params.keys & ALLOWED_PARAMS).any?
      end

      def registry_params
        params.slice(*ALLOWED_PARAMS)
      end
    end
  end
end
