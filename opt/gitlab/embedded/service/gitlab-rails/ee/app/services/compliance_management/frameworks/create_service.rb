# frozen_string_literal: true

module ComplianceManagement
  module Frameworks
    class CreateService < BaseService
      include ::ComplianceManagement::Frameworks

      attr_reader :namespace, :params, :current_user, :framework

      def initialize(namespace:, params:, current_user:)
        @namespace = namespace&.root_ancestor
        @params = params
        @current_user = current_user
        @framework = ComplianceManagement::Framework.new
        @project_errors = []
      end

      def execute
        framework.assign_attributes(
          namespace: namespace,
          name: params[:name],
          description: params[:description],
          color: params[:color],
          pipeline_configuration_full_path: params[:pipeline_configuration_full_path],
          template_id: params[:template_id],
          template_version: params[:template_version]
        )

        return ServiceResponse.error(message: 'Not permitted to create framework') unless permitted?
        return ServiceResponse.error(message: 'Pipeline configuration full path feature is not available') unless compliance_pipeline_configuration_available?

        return error unless framework.save

        after_execute

        apply_projects unless params[:projects].blank?

        success
      end

      private

      def permitted?
        can? current_user, :admin_compliance_framework, framework
      end

      def success
        ServiceResponse.success(message: @project_errors.join(', '), payload: { framework: framework })
      end

      def audit_create
        audit_context = {
          name: 'create_compliance_framework',
          author: current_user,
          scope: framework.namespace,
          target: framework,
          message: %(Created compliance framework: "#{framework.name}")
        }

        ::Gitlab::Audit::Auditor.audit(audit_context)
      end

      def error
        ServiceResponse.error(message: _('Failed to create framework'), payload: framework.errors)
      end

      def set_default_framework
        return unless params[:default].present?

        ::Groups::UpdateService.new(
          framework.namespace,
          current_user,
          default_compliance_framework_id: framework.id
        ).execute
      end

      def after_execute
        audit_create
        set_default_framework
      end

      def apply_projects
        params[:projects][:add_projects].each do |project_id|
          project = Project.find(project_id)

          # Check if project belongs to the same group as the framework
          unless project_framework_same_namespace?(project, framework)
            @project_errors << (format(_("Project %{project_name} and framework are not from same namespace."), project_name: project.name))
            next
          end

          result = ComplianceManagement::ComplianceFramework::ProjectSetting::AddFrameworkService.new(
            project_id: project_id,
            current_user: current_user,
            framework: framework
          ).execute

          @project_errors << result.message if result.error?
        rescue ActiveRecord::RecordNotFound
          @project_errors << (format(_("Project with ID %{project_id} not found"), project_id: project_id))
        end
      end
    end
  end
end
