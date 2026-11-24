# frozen_string_literal: true

module Projects
  module ComplianceStandards
    class AdherenceFinder
      LIMIT = 100

      def initialize(group, current_user, params = {})
        @group = group
        @current_user = current_user
        @params = params
      end

      def execute
        return ::Projects::ComplianceStandards::Adherence.none unless allowed?

        if params[:include_subgroups].present?
          execute_in_operator_query
        else
          items = init_collection
          items = filter_by_projects(items)
          items = filter_by_check_name(items)
          filter_by_standard(items)
        end
      end

      private

      attr_reader :group, :current_user, :params

      def allowed?
        return true if params[:skip_authorization].present?

        Ability.allowed?(current_user, :read_compliance_adherence_report, group)
      end

      def init_collection
        if params[:skip_group_check].present?
          # group check cannot be skipped unless we have project_ids filter
          if params[:project_ids].present?
            ::Projects::ComplianceStandards::Adherence
          else
            ::Projects::ComplianceStandards::Adherence.none
          end
        else
          ::Projects::ComplianceStandards::Adherence.for_group(group)
        end
      end

      def in_operator_scope
        base_scope = ::Projects::ComplianceStandards::Adherence
        base_scope = filter_by_projects(base_scope)
        base_scope = filter_by_check_name(base_scope)
        base_scope = filter_by_standard(base_scope)

        base_scope.order_by_project_id(:desc)
      end

      def execute_in_operator_query
        Gitlab::Pagination::Keyset::InOperatorOptimization::QueryBuilder.new(
          scope: in_operator_scope,
          array_scope: group.self_and_descendant_ids,
          array_mapping_scope: ::Projects::ComplianceStandards::Adherence.method(:in_optimization_array_mapping_scope),
          finder_query: ::Projects::ComplianceStandards::Adherence.method(:in_optimization_finder_query)
        ).execute.limit(LIMIT)
      end

      def filter_by_projects(adherence_records)
        if params[:project_ids].present?
          adherence_records.for_projects(params[:project_ids])
        else
          adherence_records
        end
      end

      def filter_by_check_name(adherence_records)
        if params[:check_name].present?
          adherence_records.for_check_name(params[:check_name])
        else
          adherence_records
        end
      end

      def filter_by_standard(adherence_records)
        if params[:standard].present?
          adherence_records.for_standard(params[:standard])
        else
          adherence_records
        end
      end
    end
  end
end
