# frozen_string_literal: true

module Projects
  module Ml
    class CandidateFinder
      VALID_ORDER_BY_TYPES = %w[column metric].freeze
      VALID_ORDER_BY_COLUMNS = %w[name created_at id].freeze
      VALID_SORT = %w[asc desc].freeze
      LATERAL_METRIC_ORDER_MAX_CANDIDATES = 50_000

      def initialize(experiment, params = {})
        @experiment = experiment
        @params = params
      end

      def execute
        candidates = @experiment.candidates.including_relationships

        candidates = by_name(candidates)
        order(candidates)
      end

      # @return [String] the order that #execute applies: metric, column, or none when it falls back to the default
      def applied_order_type
        return 'metric' if order_by_metric?

        VALID_ORDER_BY_COLUMNS.include?(@params[:order_by]) ? 'column' : 'none'
      end

      private

      def by_name(candidates)
        return candidates unless @params[:name].present?

        candidates.by_name(@params[:name])
      end

      def order(candidates)
        return candidates.order_by_metric(metric_order_by, sort, lateral: lateral_metric_order?) if order_by_metric?

        candidates.order_by("#{column_order_by}_#{sort}").with_order_id_desc
      end

      def order_by_metric?
        order_by_type == 'metric'
      end

      # The lateral join looks up every candidate before the sort, so huge experiments keep the table-wide subquery.
      def lateral_metric_order?
        !@experiment.more_candidates_than?(LATERAL_METRIC_ORDER_MAX_CANDIDATES)
      end

      def order_by_type
        valid_or_default(@params[:order_by_type], VALID_ORDER_BY_TYPES, 'column')
      end

      def column_order_by
        valid_or_default(@params[:order_by], VALID_ORDER_BY_COLUMNS, 'created_at')
      end

      def metric_order_by
        @params[:order_by] || ''
      end

      def sort
        valid_or_default(@params[:sort]&.downcase, VALID_SORT, 'desc')
      end

      def valid_or_default(value, valid_values, default)
        return value if valid_values.include?(value)

        default
      end
    end
  end
end
