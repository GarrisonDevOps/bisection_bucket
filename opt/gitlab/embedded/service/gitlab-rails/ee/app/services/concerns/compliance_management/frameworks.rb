# frozen_string_literal: true

module ComplianceManagement
  module Frameworks
    def compliance_pipeline_configuration_available?
      return true if params[:pipeline_configuration_full_path].blank?

      can?(current_user, :update_compliance_pipeline_configuration, framework)
    end

    def project_framework_same_namespace?(project, framework)
      project.root_ancestor&.id == framework.namespace_id ||
        framework_belongs_to_csp(framework)
    end

    private

    def framework_belongs_to_csp(framework)
      framework.namespace_id == csp_namespace_id(framework)
    end

    def csp_namespace_id(framework)
      ::Security::PolicySetting.in_organization(
        framework.namespace.organization
      )&.csp_namespace_id
    end
  end
end
