# frozen_string_literal: true

module Security
  module InventoryFilters
    class ProjectsFinderService
      include ::Gitlab::Pagination::GraphqlKeysetPagination

      CAPPED_COUNT_LIMIT = 1_000

      def initialize(namespace:, params: {})
        @namespace = namespace
        @params = params
      end

      def execute
        scope = build_filtered_scope
        result = paginate_with_keyset(scope)
        project_ids = result[:records].map(&:project_id)

        {
          ids: project_ids,
          page_info: result[:page_info],
          count: -> { scope.unordered.limit(CAPPED_COUNT_LIMIT + 1).count }
        }
      end

      private

      attr_reader :namespace, :params

      def base_scope
        Security::InventoryFilter
          .unarchived
          .select(:traversal_ids, :project_id)
      end

      def build_filtered_scope
        scope = base_scope
        scope = filter_by_subgroups(scope)
        scope = filter_by_vulnerability_counts(scope)
        scope = filter_by_analyzers_statuses(scope)
        scope = filter_by_security_attributes(scope)
        scope = filter_by_aggregate_booleans(scope)
        scope = filter_by_triage_trigger(scope)
        scope = apply_sort(scope)
        filter_by_search(scope)
      end

      def apply_sort(scope)
        analyzer = params[:sort_by]&.to_sym
        unless Security::InventoryFilter::SORTABLE_ANALYZER_COLUMNS.include?(analyzer)
          return scope.order_by_traversal_and_project
        end

        scope.order_by_analyzer_status(analyzer)
      end

      def filter_by_subgroups(scope)
        return scope.within(namespace.traversal_ids) if params[:include_subgroups]

        scope.by_traversal_ids(namespace.traversal_ids)
      end

      def filter_by_vulnerability_counts(scope)
        return scope unless params[:vulnerability_count_filters].present?

        params[:vulnerability_count_filters].each do |filter|
          scope = scope.by_severity_count(filter[:severity], filter[:operator], filter[:count])
        end

        scope
      end

      def filter_by_analyzers_statuses(scope)
        return scope unless params[:security_analyzer_filters].present?

        params[:security_analyzer_filters].each do |filter|
          scope = scope.by_analyzer_status(filter[:analyzer_type], filter[:status])
        end

        scope
      end

      def filter_by_security_attributes(scope)
        return scope unless params[:attribute_filters].present?

        is_one_of_filters = []
        is_not_one_of_filters = []

        params[:attribute_filters].each do |filter|
          next if filter[:attributes].blank?

          if filter[:operator] == 'is_one_of'
            is_one_of_filters << filter[:attributes]
          elsif filter[:operator] == 'is_not_one_of'
            is_not_one_of_filters << filter[:attributes]
          end
        end

        scope.by_security_attributes(is_one_of_filters, is_not_one_of_filters)
      end

      def filter_by_aggregate_booleans(scope)
        scope = scope.by_has_scanners(params[:has_scanners]) unless params[:has_scanners].nil?
        scope = scope.by_has_stale(params[:has_stale]) unless params[:has_stale].nil?
        unless params[:has_failed_or_warning].nil?
          scope = scope.by_has_failed_or_warning(params[:has_failed_or_warning])
        end

        scope
      end

      def filter_by_triage_trigger(scope)
        return scope unless params[:trigger_type].present?

        scope.by_triage_trigger(params[:trigger_type])
      end

      def filter_by_search(scope)
        return scope unless params[:search].present?

        scope.search(params[:search])
      end
    end
  end
end
