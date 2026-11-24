# frozen_string_literal: true

module ComplianceManagement
  module ComplianceFramework
    module ComplianceRequirements
      class BaseRequirementsService < BaseService
        InvalidControlError = Class.new(StandardError)

        private

        attr_reader :params, :current_user, :requirement, :controls

        def control_limit_error
          ServiceResponse.error(
            message: format(_('More than %{control_count} controls not allowed for a requirement.'),
              control_count: ComplianceManagement::ComplianceFramework::ComplianceRequirementsControl::
                  MAX_COMPLIANCE_CONTROLS_PER_REQUIREMENT_COUNT
            )
          )
        end

        def control_count_exceeded?
          return false if controls.nil?

          controls.length > ComplianceManagement::ComplianceFramework::ComplianceRequirementsControl::
              MAX_COMPLIANCE_CONTROLS_PER_REQUIREMENT_COUNT
        end

        def success
          ServiceResponse.success(payload: { requirement: requirement })
        end

        def invalid_control_response(control_name, error_message)
          format(_("Failed to add compliance requirement control %{control_name}: %{error_message}"),
            control_name: control_name, error_message: error_message
          )
        end

        def add_controls
          control_objects = []

          controls.each do |control_params|
            control_object = build_control(control_params)
            validate_control!(control_object)

            control_objects << control_object
          rescue ArgumentError, ActiveRecord::RecordInvalid => e
            raise InvalidControlError, invalid_control_response(control_params[:name], e.message)
          end

          persist_controls!(control_objects)
        rescue ActiveRecord::RecordNotUnique
          raise InvalidControlError, _("Duplicate entries found for compliance controls for the requirement.")
        end

        def enqueue_project_framework_evaluation
          return if controls.nil? || controls.empty?

          ComplianceManagement::ComplianceFramework::ProjectsComplianceEnqueueWorker.perform_async(
            requirement.framework_id
          )
        end

        def build_control(control_params)
          ComplianceManagement::ComplianceFramework::ComplianceRequirementsControl.new(
            compliance_requirement: requirement,
            namespace_id: requirement.namespace_id,
            name: control_params[:name],
            expression: control_params[:expression],
            control_type: control_params[:control_type] || 'internal',
            secret_token: control_params[:secret_token],
            external_url: control_params[:external_url],
            external_control_name: control_params[:external_control_name],
            ping_enabled: control_params[:ping_enabled].nil? || control_params[:ping_enabled]
          )
        end

        def validate_control!(control)
          control.validate!
        end

        def persist_controls!(control_objects)
          return if control_objects.empty?

          control_attributes = control_objects.map do |obj|
            obj.attributes.except('secret_token', 'id', 'created_at', 'updated_at')
          end

          ComplianceManagement::ComplianceFramework::ComplianceRequirementsControl.insert_all!(control_attributes)
        end
      end
    end
  end
end
