# frozen_string_literal: true

module Sbom
  # rubocop:disable CodeReuse/ActiveRecord -- Code won't be reused outside this context
  class AggregationsFinder
    include Gitlab::Utils::StrongMemoize

    DEFAULT_PAGE_SIZE = 20
    MAX_PAGE_SIZE = 20
    DEFAULT_SORT_COLUMNS = %i[component_id component_version_id].freeze
    SUPPORTED_SORT_COLUMNS = %i[
      component_name
      highest_severity
      package_manager
      primary_license_spdx_identifier
    ].freeze

    # Sort vocabulary shared with Sbom::DependenciesFinder#sort, which is what the
    # dependency list frontend and the GraphQL DependencySortEnum both speak.
    # Native column names from SUPPORTED_SORT_COLUMNS are still accepted.
    SORT_BY_ALIASES = {
      name: :component_name,
      packager: :package_manager,
      severity: :highest_severity,
      license: :primary_license_spdx_identifier
    }.freeze

    def initialize(namespace, params: {})
      @namespace = namespace
      @params = params
    end

    def execute
      group_columns = distinct_columns.map { |column| column_expression(column, 'outer_occurrences') }

      # JSONB_AGG also aggregates nulls, which we want to avoid.
      # The FILTER statement prevents nulls from being concatenated into the array,
      # and the COALESCE function gives us an empty array instead of NULL when there are no items.
      licenses_select = <<~SQL
        COALESCE(
          JSONB_AGG(outer_occurrences.licenses->0) FILTER (WHERE outer_occurrences.licenses->0 IS NOT NULL),
        '[]') AS licenses
      SQL

      Sbom::Occurrence
        .select(
          *group_columns,
          'MIN(outer_occurrences.id)::bigint AS id',
          'MIN(outer_occurrences.package_manager) AS package_manager',
          'MIN(outer_occurrences.input_file_path) AS input_file_path',
          'MIN(outer_occurrences.licenses -> 0 ->> \'spdx_identifier\') as primary_license_spdx_identifier',
          licenses_select,
          'SUM(counts.occurrence_count)::integer AS occurrence_count',
          'SUM(counts.vulnerability_count)::integer AS vulnerability_count',
          'SUM(counts.project_count)::integer AS project_count'
        )
        .from("(#{outer_occurrences.to_sql}) outer_occurrences, LATERAL (#{counts.to_sql}) counts")
        .group(*group_columns)
        .order(outer_order)
    end

    private

    attr_reader :namespace, :params

    def keyset_order(column_expression_evaluator:, order_expression_evaluator:)
      order_definitions = orderings.map do |column, direction|
        nullable = nullable(column, direction)
        column_expression = column_expression_evaluator.call(column)

        # rubocop:disable GitlabSecurity/PublicSend -- Only values are :not_nullable, :nulls_last, :nulls_first
        order_expression = order_expression_evaluator.call(column)
                             .then { |oe| direction == :desc ? oe.desc : oe.asc }
                             .then { |oe| nullable == :not_nullable ? oe : oe.send(nullable) }
        # rubocop:enable GitlabSecurity/PublicSend

        Gitlab::Pagination::Keyset::ColumnOrderDefinition.new(
          attribute_name: column.to_s,
          column_expression: column_expression,
          order_expression: order_expression,
          nullable: nullable,
          order_direction: direction
        )
      end

      Gitlab::Pagination::Keyset::Order.build(order_definitions)
    end

    def outer_order
      keyset_order(
        column_expression_evaluator: ->(column) { column_expression(column, 'outer_occurrences') },
        order_expression_evaluator: ->(column) { sql_min(column, 'outer_occurrences') }
      )
    end

    def namespaces
      Sbom::Occurrence.for_namespace_and_descendants(namespace).unarchived.loose_index_scan(column: :traversal_ids)
    end

    def inner_occurrences
      relation = Sbom::Occurrence
        .where('sbom_occurrences.traversal_ids = namespaces.traversal_ids')
        .unarchived

      relation = filter_by_licences(relation)
      relation = filter_by_component_ids(relation)
      relation = filter_by_component_names(relation)
      relation = filter_by_package_managers(relation)
      relation = filter_by_component_versions(relation)

      relation
        .order(inner_order)
        .select(distinct(on: distinct_columns))
        .keyset_paginate(cursor: cursor, per_page: page_size)
    end

    def filter_by_licences(relation)
      return relation unless params[:licenses].present?

      relation.by_primary_license(params[:licenses])
    end

    def filter_by_component_ids(relation)
      return relation unless params[:component_ids].present?

      relation.filter_by_component_ids(params[:component_ids])
    end

    def filter_by_component_names(relation)
      return relation unless params[:component_names].present?

      relation.filter_by_component_names(params[:component_names])
    end

    def filter_by_package_managers(relation)
      return relation if Feature.disabled?(:dependencies_page_filter_by_package_manager, namespace)
      return relation unless params[:package_managers].present?

      relation.filter_by_package_managers(params[:package_managers])
    end

    def filter_by_component_versions(relation)
      negated_filter = params.dig(:not, :component_versions)

      return relation if params[:component_versions].blank? && negated_filter.nil?

      if params[:component_versions]
        relation.filter_by_component_versions(params[:component_versions])
      else
        relation.filter_by_non_component_versions(negated_filter)
      end
    end

    def inner_order
      evaluator = ->(column) { column_expression(column) }

      keyset_order(
        column_expression_evaluator: evaluator,
        order_expression_evaluator: evaluator
      )
    end

    def outer_occurrences
      order = orderings.map do |column, direction|
        column_expression = column_expression(column, 'inner_occurrences')
        nullable = nullable(column, direction)

        # rubocop:disable GitlabSecurity/PublicSend -- Only values are :not_nullable, :nulls_last, :nulls_first
        column_expression
          .then { |oe| direction == :desc ? oe.desc : oe.asc }
          .then { |oe| nullable == :not_nullable ? oe : oe.send(nullable) }
        # rubocop:enable GitlabSecurity/PublicSend
      end

      Sbom::Occurrence.select(distinct(on: distinct_columns, table_name: 'inner_occurrences'))
      .from("(#{namespaces.to_sql}) AS namespaces, LATERAL (#{inner_occurrences.to_sql}) inner_occurrences")
      .order(*order)
      .limit(page_size + 1)
    end

    def counts
      Sbom::Occurrence.select('COUNT(project_id) AS occurrence_count')
        .select('COUNT(DISTINCT project_id) project_count')
        .select('SUM(vulnerability_count) vulnerability_count')
        .for_namespace_and_descendants(namespace)
        .unarchived
        .where('sbom_occurrences.component_version_id = outer_occurrences.component_version_id')
    end

    def page_size
      [params.fetch(:per_page, DEFAULT_PAGE_SIZE).to_i, MAX_PAGE_SIZE].min
    end

    def cursor
      params[:cursor]
    end

    def distinct_columns
      orderings.keys
    end

    def column_expression(column, table_name = 'sbom_occurrences')
      if column == :primary_license_spdx_identifier
        Sbom::Occurrence.adapter_class.quote_table_name(table_name)
          .then { |table_name| Arel.sql("(#{table_name}.\"licenses\" -> 0 ->> 'spdx_identifier')::text") }
      else
        Sbom::Occurrence.arel_table.alias(table_name)[column]
      end
    end

    def distinct(on:, table_name: 'sbom_occurrences')
      select_values = Sbom::Occurrence.column_names.map do |column|
        Sbom::Occurrence.adapter_class.quote_table_name("#{table_name}.#{column}")
      end
      distinct_values = on.map { |column| column_expression(column, table_name) }

      distinct_sql = Arel::Nodes::DistinctOn.new(distinct_values).to_sql

      "#{distinct_sql} #{select_values.join(', ')}"
    end

    def sql_min(column, table_name = 'sbom_occurrences')
      Arel::Nodes::NamedFunction.new('MIN', [column_expression(column, table_name)])
    end

    def nullable(column_name, direction)
      return :not_nullable if column_name == :primary_license_spdx_identifier

      column = Sbom::Occurrence.columns_hash[column_name.to_s]

      return :not_nullable unless column.null
      return direction == :desc ? :nulls_last : :nulls_first if column_name == :highest_severity

      # The default behavior for postgres is to have nulls first
      # when in descending order, and nulls last otherwise.
      direction == :desc ? :nulls_first : :nulls_last
    end

    def orderings
      default_orderings = DEFAULT_SORT_COLUMNS.index_with { sort_direction }

      return default_orderings unless sort_by.present?

      # The `sort_by` column must come first in the `ORDER BY` statement.
      # Create a new hash to ensure that it is in the front when enumerating.
      Hash[sort_by => sort_direction, **default_orderings]
    end
    strong_memoize_attr :orderings

    def sort_by
      sort_by = params[:sort_by]&.to_sym
      sort_by = SORT_BY_ALIASES.fetch(sort_by, sort_by)

      return unless sort_by && SUPPORTED_SORT_COLUMNS.include?(sort_by)

      sort_by
    end
    strong_memoize_attr :sort_by

    def sort_direction
      params[:sort]&.downcase&.to_sym == :desc ? :desc : :asc
    end
  end
  # rubocop:enable CodeReuse/ActiveRecord
end
