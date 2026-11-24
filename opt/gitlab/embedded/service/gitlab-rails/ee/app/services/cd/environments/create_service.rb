# frozen_string_literal: true

module Cd
  module Environments
    class CreateService
      def initialize(parent:, current_user: nil, params: {})
        @parent = parent
        @current_user = current_user
        @params = params.dup
        @driver_ref = @params.delete(:driver_ref)
        @driver_config = @params.delete(:driver_config)
      end

      def execute
        environment = ::Cd::Environment.new(params.merge(organization: parent))

        ::Cd::Environment.transaction do
          environment.save!
          environment.environment_driver_bindings.create!(driver_ref: driver_ref, driver_config: driver_config)
        end

        ServiceResponse.success(payload: { environment: environment })
      rescue ActiveRecord::RecordInvalid => e
        ServiceResponse.error(message: e.record.errors.full_messages, payload: { environment: environment })
      end

      private

      attr_reader :parent, :current_user, :params, :driver_ref, :driver_config
    end
  end
end
