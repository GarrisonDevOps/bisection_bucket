# frozen_string_literal: true

module Security
  module Ascp
    class CreateComponentService
      def initialize(current_user:, project:, params:)
        @current_user = current_user
        @project = project
        @params = params
      end

      def execute
        validation_error = validate
        return validation_error if validation_error

        create_component
      end

      private

      attr_reader :current_user, :project, :params

      def validate
        validate_permission || validate_scan
      end

      def validate_permission
        return if Ability.allowed?(current_user, :create_ascp_component, project)

        ServiceResponse.error(message: 'Insufficient permissions')
      end

      def validate_scan
        return if scan

        ServiceResponse.error(message: 'Scan not found in this project')
      end

      def create_component
        component = Component.new(
          project: project,
          scan: scan,
          title: params[:title],
          sub_directory: params[:sub_directory],
          description: params[:description],
          expected_user_behavior: params[:expected_user_behavior]
        )

        if component.save
          ServiceResponse.success(payload: { component: component })
        else
          ServiceResponse.error(message: component.errors.full_messages.to_sentence)
        end
      end

      def scan
        @scan ||= Scan.find_for_project(params[:scan_id], project.id)
      end
    end
  end
end
