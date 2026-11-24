# frozen_string_literal: true

module Cd
  module EnvironmentDriverBindings
    class CreateService
      def initialize(parent:, current_user: nil, params: {})
        @parent = parent
        @current_user = current_user
        @params = params.dup
      end

      def execute
        binding = ::Cd::EnvironmentDriverBinding.new(params.merge(environment: parent))

        if binding.save
          ServiceResponse.success(payload: { environment_driver_binding: binding })
        else
          error(binding)
        end
      rescue ActiveRecord::RecordNotUnique
        binding.errors.add(:version, :taken) if binding.errors[:version].blank?
        error(binding)
      end

      private

      attr_reader :parent, :current_user, :params

      def error(binding)
        ServiceResponse.error(
          message: binding.errors.full_messages,
          payload: { environment_driver_binding: binding }
        )
      end
    end
  end
end
