# frozen_string_literal: true

module ComplianceManagement
  module ComplianceFramework
    module ComplianceRequirements
      class UpdateService < BaseRequirementsService
        def initialize(requirement:, params:, current_user:, controls:)
          @requirement = requirement
          @params = params
          @current_user = current_user
          @controls = controls
        end

        def execute
          return ServiceResponse.error(message: _('Not permitted to update requirement')) unless permitted?
          return control_limit_error if control_count_exceeded?

          begin
            ComplianceManagement::ComplianceFramework::ComplianceRequirement.transaction do
              requirement.update!(params)

              update_controls
            end
          rescue ActiveRecord::RecordInvalid
            return error
          rescue InvalidControlError => e
            return ServiceResponse.error(message: e.message, payload: e.message)
          end

          enqueue_project_framework_evaluation
          audit_changes

          success
        end

        private

        def permitted?
          can? current_user, :admin_compliance_framework, requirement.framework
        end

        def audit_changes
          requirement.previous_changes.each do |attribute, changes|
            next if attribute.eql?('updated_at')

            audit_context = {
              name: 'update_compliance_requirement',
              author: current_user,
              scope: requirement.framework.namespace,
              target: requirement,
              message: "Changed compliance requirement's #{attribute} from #{changes[0]} to #{changes[1]}"
            }

            ::Gitlab::Audit::Auditor.audit(audit_context)
          end
        end

        def error
          ServiceResponse.error(message: _('Failed to update compliance requirement'), payload: requirement.errors)
        end

        def update_controls
          return if controls.nil?

          existing_controls = requirement.compliance_requirements_controls
          new_control_params = controls.map(&:to_h)

          process_existing_controls(existing_controls, new_control_params)

          controls_to_add = filter_new_controls(existing_controls, new_control_params)

          return unless controls_to_add.any?

          @controls = controls_to_add
          add_controls
        end

        def process_existing_controls(existing_controls, new_control_params)
          existing_controls.each do |control|
            matching_param = find_matching_param(control, new_control_params)

            if matching_param
              update_control(control, matching_param)
            else
              destroy_control(control)
            end
          end
        end

        def filter_new_controls(existing_controls, new_control_params)
          new_control_params.reject do |params|
            existing_controls.any? { |control| control_matches?(control, params) }
          end
        end

        def find_matching_param(control, params_list)
          params_list.find { |params| control_matches?(control, params) }
        end

        def control_matches?(control, params)
          if control.external? && params[:external_url].present?
            control.external_url == params[:external_url]
          else
            control.name == params[:name]
          end
        end

        def destroy_control(control)
          response = ComplianceRequirementsControls::DestroyService.new(
            control: control,
            current_user: current_user
          ).execute

          return if response.success?

          raise InvalidControlError, format(
            _("Control '%{name}': %{error}"),
            name: control.name,
            error: response.message
          )
        end

        def update_control(control, params)
          response = ComplianceRequirementsControls::UpdateService.new(
            control: control,
            params: params,
            current_user: current_user
          ).execute

          return if response.success?

          raise InvalidControlError, format(
            _("Control '%{name}': %{error}"),
            name: control.name,
            error: response.message
          )
        end
      end
    end
  end
end
