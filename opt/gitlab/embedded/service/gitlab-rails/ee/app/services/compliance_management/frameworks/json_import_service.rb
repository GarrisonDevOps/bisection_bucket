# frozen_string_literal: true

module ComplianceManagement
  module Frameworks
    class JsonImportService
      def initialize(user:, group:, json_payload:)
        @user = user
        @group = group
        @json_payload = json_payload
        @requirement_errors = []
        @control_errors = []
      end

      def execute
        return ServiceResponse.error(message: 'invalid json payload - must be a Hash') unless json_payload.is_a?(Hash)

        @json_payload = json_payload.with_indifferent_access

        framework_response = import_framework

        return error(framework_response:) if framework_response.error?

        @framework = framework_response.payload[:framework]
        import_requirements
        success
      end

      private

      attr_reader :user, :group, :framework, :json_payload

      def success
        success_message = (@requirement_errors + @control_errors).reject(&:blank?).join(", ")
        ServiceResponse.success(message: success_message, payload: { framework: framework })
      end

      def error(framework_response:)
        errors = framework_response.payload
        errors = errors.full_messages.join(", ") if errors.respond_to? :full_messages
        ServiceResponse.error(message: framework_response.message, payload: errors)
      end

      def import_framework
        ComplianceManagement::Frameworks::CreateService.new(
          namespace: group,
          params: framework_payload,
          current_user: user
        ).execute
      end

      def framework_payload
        json_payload.slice(:name, :description, :color, :template_id, :template_version, :default)
      end

      def import_requirements
        requirements_payload.each do |requirement|
          result = ComplianceManagement::ComplianceFramework::ComplianceRequirements::CreateService.new(
            framework: @framework,
            params: requirement.slice(:name, :description),
            current_user: user
          ).execute

          if result.success?
            import_controls(
              requirement: result.payload[:requirement],
              controls: Array.wrap(requirement[:controls])
            )
          end

          next unless result.error?

          created_requirement = result.payload
          errors = created_requirement.full_messages.join(", ") if created_requirement.respond_to? :full_messages
          error_messages = "#{result.message} #{errors}"

          @requirement_errors <<
            "Requirement errors: #{error_messages}"
        end
      end

      def requirements_payload
        Array.wrap json_payload[:requirements]
      end

      def import_controls(requirement:, controls:)
        controls.each do |control|
          result = ComplianceManagement::ComplianceFramework::ComplianceRequirementsControls::CreateService.new(
            requirement: requirement,
            params: control_payload(control),
            current_user: user
          ).execute

          next unless result.error?

          control = result.payload
          errors = control.full_messages.join(", ") if control.respond_to? :full_messages
          error_messages = "#{result.message} #{errors}"

          @control_errors <<
            "Requirement ID: #{requirement.id} control errors: #{error_messages}"
        rescue ArgumentError => e
          @control_errors <<
            "Requirement ID: #{requirement.id} control errors: #{e.message}"
        end
      end

      def control_payload(params)
        expression = params[:expression]
        params[:expression] = expression.to_json if expression.is_a? Hash
        params
      end
    end
  end
end
