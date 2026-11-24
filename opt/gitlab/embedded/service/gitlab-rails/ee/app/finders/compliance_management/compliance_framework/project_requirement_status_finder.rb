# frozen_string_literal: true

module ComplianceManagement
  module ComplianceFramework
    class ProjectRequirementStatusFinder
      include ::Gitlab::Utils::StrongMemoize

      LIMIT = 100
      MAX_LIMIT = 10_000

      def initialize(group, current_user, params = {})
        @group = group
        @current_user = current_user
        @skip_limit = params.delete(:skip_limit) || false
        @params = params
      end

      def execute
        return model.none unless allowed?

        # If records need to be filtered by project then we don't need inoperator optimization as we are already
        # dealing with just a single project.
        if project.present?
          base_scope
        else
          records_for_group
        end
      end

      private

      attr_reader :group, :current_user, :params, :skip_limit

      def allowed?
        [project, group].any? do |subject|
          Ability.allowed?(current_user, :read_compliance_adherence_report, subject)
        end
      end

      def model
        ::ComplianceManagement::ComplianceFramework::ProjectRequirementComplianceStatus
      end

      def records_for_group
        scope = Gitlab::Pagination::Keyset::InOperatorOptimization::QueryBuilder.new(
          scope: base_scope,
          array_scope: group.self_and_descendant_ids,
          array_mapping_scope: model.method(:in_optimization_array_mapping_scope),
          finder_query: model.method(:in_optimization_finder_query)
        ).execute

        if skip_limit
          scope.limit(MAX_LIMIT)
        else
          scope.limit(LIMIT)
        end
      end

      def base_scope
        base_scope = model
        base_scope = filter_by_project(base_scope)
        base_scope = filter_by_requirement(base_scope)
        base_scope = filter_by_framework(base_scope)

        order_by_scope(base_scope)
      end

      def order_by_scope(base_scope)
        case params[:order_by]
        when 'project'
          base_scope.order_by_project_and_id
        when 'requirement'
          base_scope.order_by_requirement_and_id
        when 'framework'
          base_scope.order_by_framework_and_id
        else
          base_scope.order_by_updated_at_and_id(:desc)
        end
      end

      def filter_by_project(status_records)
        return status_records.for_projects(params[:project_id]) if params[:project_id].present?

        status_records
      end

      def filter_by_requirement(status_records)
        return status_records.for_requirements(params[:requirement_id]) if params[:requirement_id].present?

        status_records
      end

      def filter_by_framework(status_records)
        return status_records.for_frameworks(params[:framework_id]) if params[:framework_id].present?

        status_records
      end

      def project
        Project.find_by_id(params[:project_id])
      end
      strong_memoize_attr :project
    end
  end
end
