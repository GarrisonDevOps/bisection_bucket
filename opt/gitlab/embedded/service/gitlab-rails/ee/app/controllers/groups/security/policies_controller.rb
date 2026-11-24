# frozen_string_literal: true

module Groups
  module Security
    class PoliciesController < Groups::ApplicationController
      include GovernUsageGroupTracking
      include SecurityPoliciesPermissions

      before_action :authorize_read_security_orchestration_policies!, except: :edit
      before_action :ensure_security_policy_project_is_available!, only: :edit
      before_action :authorize_modify_security_policy!, only: :edit
      before_action :ensure_policy_type_is_available!, only: [:new, :edit]
      before_action :validate_policy_configuration, only: :edit

      before_action do
        push_force_frontend_feature_flag(:dependency_firewall_access,
          ::Security::DependencyFirewall::Availability.access_enabled?(group))
        push_force_frontend_feature_flag(:dependency_firewall_package_version,
          ::Security::DependencyFirewall::Availability.package_version_enabled?(group))
        push_frontend_feature_flag(:security_policy_eligible_projects_dropdown, group)
      end

      feature_category :security_policy_management
      urgency :default, [:edit]
      urgency :low, [:index, :new]
      track_govern_activity 'security_policies', :index, :edit, :new

      def new
        @policy_type = policy_params[:type]
      end

      def edit
        @policy_name = URI.decode_www_form_component(policy_params[:id])
        @policy = policy

        render_404 if @policy.nil?
      end

      def index
        render :index, locals: { group: group }
      end

      def schema
        render json: ::Security::OrchestrationPolicyConfiguration::POLICY_SCHEMA_JSON
      end

      private

      def container
        group
      end

      def policy_params
        params.permit(:type, :id)
      end

      def policy_configuration_invalid_component_and_message
        @policy_type = policy_params[:type].presence&.to_sym

        result = ::Security::SecurityOrchestrationPolicies::PolicyConfigurationValidationService.new(
          policy_configuration: policy_configuration,
          type: @policy_type
        ).execute

        [result[:invalid_component], result[:message]] if result[:status] == :error
      end

      def validate_policy_configuration
        invalid_component, error_message = policy_configuration_invalid_component_and_message

        return unless invalid_component

        case invalid_component
        when :policy_project
          redirect_to project_path(policy_configuration.security_policy_management_project), alert: error_message
        when :policy_yaml
          policy_management_project = policy_configuration.security_policy_management_project
          policy_path = File.join(
            policy_management_project.default_branch,
            ::Security::OrchestrationPolicyConfiguration::POLICY_PATH
          )

          redirect_to project_blob_path(policy_management_project, policy_path), alert: error_message
        else
          redirect_to group_security_policies_path(group), alert: error_message
        end
      end

      def ensure_security_policy_project_is_available!
        render_404 if policy_configuration.blank?
      end

      def policy
        result = ::Security::SecurityOrchestrationPolicies::FetchPolicyService.new(
          policy_configuration: policy_configuration,
          name: @policy_name,
          type: @policy_type
        ).execute

        result[:policy].presence
      end

      def policy_configuration
        @policy_configuration ||= group.security_orchestration_policy_configuration
      end
    end
  end
end
