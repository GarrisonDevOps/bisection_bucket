# frozen_string_literal: true

# Security::FindingsFinder
#
# This finder returns an `ActiveRecord::Relation` of the
# `Security::Finding`s associated with a pipeline.
#
# Arguments:
#   pipeline - object to filter findings
#   params:
#     severity:             Array<String>
#     report_type:          Array<String>
#     scan_mode:            String
#     scope:                String
#     related_pipeline_ids: Array<Integer> - additional pipelines (for example, sibling
#                           pipelines for the same sha) whose findings should be included
#     lean:                 Boolean - select only LEAN_COLUMNS and skip eager loading.
#                           Used for report comparison, where only identity and
#                           severity are needed and `finding_data` would dominate memory.

module Security
  class FindingsFinder
    DEFAULT_PER_PAGE = 20
    LEAN_COLUMNS = %w[id scan_id scanner_id severity uuid context_unaware_uuid partition_number].freeze

    def initialize(pipeline, params: {})
      @pipeline = pipeline
      @params = params
    end

    def execute
      # This method generates a query of the general form
      #
      #   SELECT security_findings.*
      #   FROM security_scans
      #   LATERAL (
      #     SELECT * FROM security_findings
      #     WHERE ...
      #   )
      #   WHERE security_scans.x = 'y'
      #   ORDER BY ...
      #   LIMIT n
      #
      # This is done for performance reasons to reduce the amount of data loaded
      # in the query compared to a more conventional
      #
      #   SELECT security_findings.*
      #   FROM security_findings
      #   JOIN security_scans ...
      #
      # The latter form can end up reading a very large number of rows on projects
      # with high numbers of findings.

      return Security::Finding.none unless pipeline

      lateral_relation = Security::Finding
        .where('"security_findings"."scan_id" = "security_scans"."id"') # rubocop:disable CodeReuse/ActiveRecord
        .then { |relation| select_lean_columns(relation) }
        .then { |relation| by_severity_filter(relation) }
        .by_partition_number(partition_numbers)
        .deduplicated
        .ordered(params[:sort])
        .then { |relation| by_uuid(relation) }
        .then { |relation| by_scanner_external_ids(relation) }
        .then { |relation| by_state(relation) }
        .then { |relation| by_include_dismissed(relation) }
        .then { |relation| by_scan_mode(relation) }
        .keyset_paginate(cursor: params[:cursor], per_page: params[:limit] || DEFAULT_PER_PAGE)

      from_sql = <<~SQL.squish
          "security_scans",
          unnest('{#{severities.join(',')}}'::smallint[]) AS "severities" ("severity"),
          LATERAL (#{lateral_relation.to_sql}) AS "security_findings"
      SQL

      Security::Finding
        .from(from_sql) # rubocop:disable CodeReuse/ActiveRecord
        .then { |relation| preload_associations(relation) }
        .merge(::Security::Scan.by_pipeline_ids(pipeline_ids))
        .merge(::Security::Scan.latest_successful)
        .then { |relation| by_report_types(relation) }
        .ordered(params[:sort])
    end

    private

    attr_reader :pipeline, :params

    delegate :project, :security_findings_partition_number, to: :pipeline, private: true

    # rubocop:disable Database/AvoidUsingPluckWithoutLimit, CodeReuse/ActiveRecord -- Limited by pipeline hierarchy size
    def pipeline_ids
      @pipeline_ids ||= pipeline.self_and_project_descendants.pluck(:id) | Array(params[:related_pipeline_ids])
    end

    def partition_numbers
      numbers = Security::Scan.by_pipeline_ids(pipeline_ids).distinct.pluck(:findings_partition_number)
      numbers.presence || [Security::Finding.active_partition_number]
    end
    # rubocop:enable Database/AvoidUsingPluckWithoutLimit, CodeReuse/ActiveRecord

    def lean?
      params[:lean].present?
    end

    def select_lean_columns(relation)
      return relation unless lean?

      relation.select(LEAN_COLUMNS.map { |column| "\"security_findings\".\"#{column}\"" })
    end

    def preload_associations(relation)
      return relation if lean?

      relation.preload_report_associations
    end

    def include_dismissed?
      params[:scope] == 'all' || params[:state]
    end

    def by_include_dismissed(relation)
      return relation if include_dismissed?

      relation.undismissed_by_vulnerability
    end

    def by_scanner_external_ids(relation)
      return relation unless params[:scanner].present?

      relation.by_scanners(project.vulnerability_scanners.with_external_id(params[:scanner]))
    end

    def by_state(relation)
      return relation unless params[:state].present?

      relation.by_state(params[:state])
    end

    def by_report_types(relation)
      return relation unless params[:report_type]

      relation.merge(::Security::Scan.by_scan_types(params[:report_type]))
    end

    def by_scan_mode(relation)
      scan_mode = params.fetch(:scan_mode, 'all')

      return relation if scan_mode == 'all'

      exists_clause = <<~SQL
        EXISTS (
          SELECT
            1
          FROM
            "vulnerability_partial_scans"
          WHERE
            "vulnerability_partial_scans"."scan_id" = "security_scans"."id"
        )
      SQL

      # rubocop:disable CodeReuse/ActiveRecord -- Requires lateral join with security scans
      case scan_mode
      when 'full'
        relation.where.not(exists_clause)
      when 'partial'
        relation.where(exists_clause)
      else
        relation
      end
      # rubocop:enable CodeReuse/ActiveRecord
    end

    def severities
      if params[:severity]
        Security::Finding.severities.fetch_values(*params[:severity])
      else
        Security::Finding.severities.values
      end
    end

    def by_uuid(relation)
      return relation unless params[:uuid]

      relation.by_uuid(params[:uuid])
    end

    # rubocop:disable CodeReuse/ActiveRecord -- Requires lateral join with security scans
    def by_severity_filter(relation)
      relation.where('"security_findings"."severity" = "severities"."severity"')
    end
    # rubocop:enable CodeReuse/ActiveRecord
  end
end
