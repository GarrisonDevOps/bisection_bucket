# frozen_string_literal: true

module Security
  class InventoryFilter < ::SecApplicationRecord
    include ::Namespaces::Traversal::Traversable
    include Gitlab::SQL::Pattern

    self.table_name = 'security_inventory_filters'

    ANALYZER_COLUMNS = Enums::Security.extended_analyzer_types.keys

    SORTABLE_ANALYZER_COLUMNS = %i[sast dependency_scanning secret_detection].freeze
    STATUS_SORT_PRIORITY = %i[failed stale not_configured success].freeze

    belongs_to :project
    validates :archived, allow_nil: false, inclusion: { in: [true, false] }
    validates :has_scanners, :has_failed_or_warning, :has_stale, inclusion: { in: [true, false] }

    # Analyzer statuses
    Enums::Security.extended_analyzer_types.each_key do |analyzer_type|
      enum analyzer_type.to_sym, Enums::Security.analyzer_statuses, prefix: true
      validates analyzer_type, presence: true
    end

    # vulnerability counts
    validates :total, presence: true, numericality: { greater_than_or_equal_to: 0 }
    validates :critical, presence: true, numericality: { greater_than_or_equal_to: 0 }
    validates :high, presence: true, numericality: { greater_than_or_equal_to: 0 }
    validates :medium, presence: true, numericality: { greater_than_or_equal_to: 0 }
    validates :low, presence: true, numericality: { greater_than_or_equal_to: 0 }
    validates :info, presence: true, numericality: { greater_than_or_equal_to: 0 }
    validates :unknown, presence: true, numericality: { greater_than_or_equal_to: 0 }

    validates :project_name, presence: true
    validates :traversal_ids, presence: true

    scope :by_project_id, ->(project_id) { where(project_id: project_id) }
    scope :by_traversal_ids, ->(traversal_ids) { where(traversal_ids: traversal_ids) }
    scope :order_by_project_id_asc, -> { order(project_id: :asc) }
    scope :unarchived, -> { where(archived: false) }
    scope :unordered, -> { reorder(nil) }
    scope :with_triage_coverage, -> { where.not(triage_capabilities_on: 0) }

    # Builds a keyset order so SimpleOrderBuilder uses it as is and does not add the `id` primary
    # key as a tiebreaker. `project_id` is unique on this table which makes the `id` addition redundant
    scope :order_by_traversal_and_project, -> {
      reorder(
        Gitlab::Pagination::Keyset::Order.build([
          Gitlab::Pagination::Keyset::ColumnOrderDefinition.new(
            attribute_name: :traversal_ids,
            order_expression: arel_table[:traversal_ids].asc,
            sql_type: 'bigint[]'
          ),
          Gitlab::Pagination::Keyset::ColumnOrderDefinition.new(
            attribute_name: :project_id,
            order_expression: arel_table[:project_id].asc,
            sql_type: 'bigint'
          )
        ])
      )
    }

    scope :order_by_analyzer_status, ->(analyzer_type) {
      unless SORTABLE_ANALYZER_COLUMNS.include?(analyzer_type.to_sym)
        raise ArgumentError, "unsupported analyzer: #{analyzer_type}"
      end

      status_ranks = STATUS_SORT_PRIORITY.map { |status| Enums::Security.analyzer_statuses.fetch(status) }
      sort_expr = Arel.sql(
        "array_position(ARRAY[#{status_ranks.join(',')}], #{connection.quote_column_name(analyzer_type)})"
      )

      select(sort_expr.as('status_rank')).reorder(
        Gitlab::Pagination::Keyset::Order.build([
          Gitlab::Pagination::Keyset::ColumnOrderDefinition.new(
            attribute_name: :status_rank,
            order_expression: sort_expr.asc,
            reversed_order_expression: sort_expr.desc,
            column_expression: sort_expr,
            sql_type: 'integer',
            nullable: :not_nullable
          ),
          Gitlab::Pagination::Keyset::ColumnOrderDefinition.new(
            attribute_name: :project_id,
            order_expression: arel_table[:project_id].asc,
            sql_type: 'bigint',
            nullable: :not_nullable
          )
        ])
      )
    }

    scope :by_has_scanners, ->(value) { where(has_scanners: value) }
    scope :by_has_failed_or_warning, ->(value) { where(has_failed_or_warning: value) }
    scope :by_has_stale, ->(value) { where(has_stale: value) }
    scope :by_severity_count, ->(severity, operator, count) do
      return none unless Enums::Vulnerability.severity_levels.key?(severity)

      arel_column = arel_table[severity]
      case operator.to_s
      when 'greater_than_or_equal_to'
        where(arel_column.gteq(count))
      when 'less_than_or_equal_to'
        where(arel_column.lteq(count))
      when 'equal_to'
        where(arel_column.eq(count))
      else
        none
      end
    end
    scope :by_analyzer_status, ->(analyzer_type, status) do
      analyzer_type = analyzer_type.downcase.to_sym
      return none unless Enums::Security.extended_analyzer_types.key?(analyzer_type)

      where(arel_table[analyzer_type].eq(Enums::Security.analyzer_statuses[status.to_sym]))
    end

    scope :by_triage_trigger, ->(trigger_type, auto_only: false) do
      mask = Security::TriageCoverage::CapabilityBitmask.mask_for(trigger_type)
      return none unless mask

      column = auto_only ? :triage_capabilities_auto : :triage_capabilities_on
      with_triage_coverage.where("#{table_name}.#{column} & ? > 0", mask)
    end

    scope :by_security_attributes, ->(is_one_of_filters, is_not_one_of_filters) do
      return none if is_one_of_filters.empty? && is_not_one_of_filters.empty?

      scope = all

      is_one_of_filters.each do |attribute_ids|
        sanitized_ids = attribute_ids.map(&:to_i)
        scope = scope.where(
          "EXISTS (
            SELECT 1 FROM project_to_security_attributes
            WHERE project_id = security_inventory_filters.project_id
            AND security_attribute_id = ANY(ARRAY[?])
          )", sanitized_ids
        )
      end

      is_not_one_of_filters.each do |attribute_ids|
        sanitized_ids = attribute_ids.map(&:to_i)
        scope = scope.where(
          "NOT EXISTS (
            SELECT 1 FROM project_to_security_attributes
            WHERE project_id = security_inventory_filters.project_id
            AND security_attribute_id = ANY(ARRAY[?])
          )", sanitized_ids
        )
      end

      scope
    end

    def self.search(query)
      fuzzy_search(query, [:project_name], use_minimum_char_limit: true)
    end

    def self.recompute_aggregate_booleans(project_ids)
      return if project_ids.empty?

      statuses = Enums::Security.analyzer_statuses

      by_project_id(project_ids).update_all(
        has_scanners: analyzer_status_not_eq(statuses[:not_configured]),
        has_failed_or_warning: analyzer_status_eq(statuses[:failed]),
        has_stale: analyzer_status_eq(statuses[:stale])
      )
    end

    def self.update_archived_for(project_ids, archived:)
      by_project_id(project_ids).where.not(archived: archived).update_all(archived: archived)
    end

    def self.analyzer_status_eq(status)
      analyzer_columns_or_sql { |column| column.eq(status) }
    end

    def self.analyzer_status_not_eq(status)
      analyzer_columns_or_sql { |column| column.not_eq(status) }
    end

    def self.analyzer_columns_or_sql
      expr = ANALYZER_COLUMNS
        .map { |column| yield arel_table[column] }
        .reduce(:or)

      Arel.sql(expr.to_sql)
    end

    def self.aggregate_posture_counters_for(namespace)
      within(namespace.traversal_ids)
        .unarchived
        .select(
          Arel.sql('COUNT(*) FILTER (WHERE has_scanners) AS with_scanners'),
          Arel.sql('COUNT(*) FILTER (WHERE has_failed_or_warning) AS with_failures'),
          Arel.sql('COUNT(*) FILTER (WHERE has_stale) AS with_stale'),
          Arel.sql('COUNT(*) FILTER (WHERE triage_capabilities_on <> 0) AS with_triage_coverage')
        )
        .take
    end

    def self.triage_coverage_counts_for(namespace, mask, missing_mask)
      within(namespace.traversal_ids)
        .unarchived
        .with_triage_coverage
        .select(
          sanitize_sql_array(["COUNT(*) FILTER (WHERE triage_capabilities_on & ? > 0) AS enabled_count", mask]),
          sanitize_sql_array(["COUNT(*) FILTER (WHERE triage_capabilities_auto & ? > 0) AS auto_count", mask]),
          sanitize_sql_array(["COUNT(*) FILTER (WHERE triage_capabilities_on & ? > 0) AS flow_missing_count",
            mask & missing_mask])
        )
        .take
    end

    def triage_capabilities
      Security::TriageCoverage::CapabilityBitmask.decode(triage_capabilities_on, triage_capabilities_auto)
    end
  end
end
