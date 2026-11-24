# frozen_string_literal: true

module ComplianceManagement
  module ComplianceFramework
    class ProjectControlStatusFinder
      def initialize(project, current_user, params = {})
        @project = project
        @current_user = current_user
        @params = params
      end

      def execute
        return model.none unless allowed?

        status_records = model.for_projects(project.id)
        filter_by_requirement(status_records)
      end

      private

      attr_reader :project, :current_user, :params

      def allowed?
        Ability.allowed?(current_user, :read_compliance_adherence_report, project)
      end

      def model
        ::ComplianceManagement::ComplianceFramework::ProjectControlComplianceStatus
      end

      def filter_by_requirement(status_records)
        if params[:compliance_requirement_id].present?
          status_records.for_requirements(params[:compliance_requirement_id])
        else
          status_records
        end
      end
    end
  end
end
