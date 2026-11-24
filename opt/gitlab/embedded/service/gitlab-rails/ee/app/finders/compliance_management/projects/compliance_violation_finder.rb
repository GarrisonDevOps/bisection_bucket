# frozen_string_literal: true

module ComplianceManagement
  module Projects
    class ComplianceViolationFinder
      include ::Gitlab::Utils::StrongMemoize

      LIMIT = 100

      def initialize(group, current_user, params = {})
        @group = group
        @current_user = current_user
        @params = params
      end

      def execute
        return model.none unless allowed?

        records_for_group
      end

      private

      attr_reader :group, :current_user, :params

      def allowed?
        Ability.allowed?(current_user, :read_compliance_violations_report, group)
      end

      def model
        ::ComplianceManagement::Projects::ComplianceViolation
      end

      def records_for_group
        Gitlab::Pagination::Keyset::InOperatorOptimization::QueryBuilder.new(
          scope: base_scope,
          array_scope: group.self_and_descendant_ids,
          array_mapping_scope: model.method(:in_optimization_array_mapping_scope),
          finder_query: model.method(:in_optimization_finder_query)
        ).execute.limit(LIMIT)
      end

      def base_scope
        base_scope = model
        base_scope = filter_by_project(base_scope)
        base_scope = filter_by_control(base_scope)
        base_scope = filter_by_status(base_scope)
        base_scope = filter_by_created_before(base_scope)
        base_scope = filter_by_created_after(base_scope)

        order_by_scope(base_scope)
      end

      def order_by_scope(base_scope)
        base_scope.order_by_created_at_and_id(:desc)
      end

      def filter_by_project(base_scope)
        return base_scope.for_projects(params[:project_id]) if params[:project_id].present?

        base_scope
      end

      def filter_by_control(base_scope)
        return base_scope.for_controls(params[:control_id]) if params[:control_id].present?

        base_scope
      end

      def filter_by_status(base_scope)
        return base_scope.for_status(params[:status]) if params[:status].present?

        base_scope
      end

      def filter_by_created_before(base_scope)
        return base_scope.created_on_or_before(params[:created_before]) if params[:created_before].present?

        base_scope
      end

      def filter_by_created_after(base_scope)
        return base_scope.created_on_or_after(params[:created_after]) if params[:created_after].present?

        base_scope
      end
    end
  end
end
