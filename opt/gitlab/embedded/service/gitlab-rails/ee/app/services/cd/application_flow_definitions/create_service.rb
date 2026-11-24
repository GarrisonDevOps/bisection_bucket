# frozen_string_literal: true

module Cd
  module ApplicationFlowDefinitions
    class CreateService
      def initialize(parent:, current_user: nil, params: {})
        @parent = parent
        @current_user = current_user
        @params = params.dup
      end

      def execute
        flow_definition = ::Cd::ApplicationFlowDefinition.new(params.merge(application: parent))

        if flow_definition.save
          ServiceResponse.success(payload: { application_flow_definition: flow_definition })
        else
          error(flow_definition)
        end
      rescue ActiveRecord::RecordNotUnique
        flow_definition.errors.add(:version, :taken) if flow_definition.errors[:version].blank?
        error(flow_definition)
      end

      private

      attr_reader :parent, :current_user, :params

      def error(flow_definition)
        ServiceResponse.error(
          message: flow_definition.errors.full_messages,
          payload: { application_flow_definition: flow_definition }
        )
      end
    end
  end
end
