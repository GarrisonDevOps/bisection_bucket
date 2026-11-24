# frozen_string_literal: true

module Gitlab
  module Database
    module Diagnostics
      module Console
        module Views
          class PlannerStatistics < Base
            RELATION_HEADERS = ['RELATION', 'KIND', 'HEAP SIZE', 'ROWS', 'LAST ANALYZE', 'INTERVAL', 'STATUS'].freeze
            EMPTY = 'No table or partitioned table is large enough to report.'
            CAPPED = "Only the first #{Checks::PlannerStatistics::RELATIONS_LIMIT} relations are listed. " \
              'The findings count every table.'.freeze

            KIND_LABELS = {
              Checks::PlannerStatistics::TABLE => 'table',
              Checks::PlannerStatistics::PARTITIONED_TABLE => 'partitioned'
            }.freeze

            NEVER_LABEL = 'never'
            NOT_RECORDED_LABEL = 'not recorded'
            UNKNOWN_LABEL = 'unknown'

            def self.title
              'Planner statistics'
            end

            private

            def print_database(database_name, payload)
              statistics = payload[:planner_statistics] || {}

              print_status(database_name, statistics)
              print_findings(statistics[:findings] || [])
              print_stats_reset(statistics[:stats_reset])
              print_relations(statistics[:relations] || [], statistics[:relations_capped])
            end

            # Analyze times older than this were discarded by PostgreSQL, so the
            # reader knows how far back the LAST ANALYZE column can see. A crash
            # or pg_upgrade drops the timestamp along with the statistics.
            def print_stats_reset(stats_reset)
              printer.key_value('Statistics reset', stats_reset ? stats_reset.utc.iso8601 : NOT_RECORDED_LABEL)
              printer.blank_line
            end

            def print_relations(relations, capped)
              return printer.detail(EMPTY) if relations.empty?

              printer.table(RELATION_HEADERS, relations.map { |relation| relation_row(relation) })
              printer.detail(CAPPED) if capped
            end

            def relation_row(relation)
              [
                "#{relation[:schema_name]}.#{relation[:table_name]}",
                KIND_LABELS.fetch(relation[:kind]),
                ActiveSupport::NumberHelper.number_to_human_size(relation[:heap_bytes]),
                rows(relation[:estimated_rows]),
                last_analyze(relation),
                interval(relation[:analyze_interval]),
                relation[:status] || OK
              ]
            end

            def rows(estimated_rows)
              return UNKNOWN_LABEL unless estimated_rows

              "~#{ActiveSupport::NumberHelper.number_to_delimited(estimated_rows)}"
            end

            # "never" only when the catalog says so; a missing timestamp on an
            # analyzed table means the statistics were reset.
            def last_analyze(relation)
              age = relation[:analyze_age_seconds]
              return "#{duration(age)} ago" if age

              relation[:status] == Checks::PlannerStatistics::MISSING ? NEVER_LABEL : UNKNOWN_LABEL
            end

            def interval(seconds)
              seconds ? duration(seconds) : ''
            end

            # The largest unit only: "3 days", not "3 days, 2 hours and 5 seconds"
            def duration(seconds)
              unit, value = ActiveSupport::Duration.build(seconds).parts.first

              "#{value} #{value == 1 ? unit.to_s.singularize : unit}"
            end
          end
        end
      end
    end
  end
end
