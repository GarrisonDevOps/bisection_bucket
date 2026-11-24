# frozen_string_literal: true

module Vulnerabilities
  module Archival
    module Export
      module Exporters
        class CsvService
          CSV_DELIMITER = '; '

          def initialize(iterator)
            @iterator = iterator
          end

          def generate(&block)
            csv_builder.render(&block)
          end

          private

          attr_reader :iterator

          def csv_builder
            @csv_builder ||= CsvBuilder.new(iterator, mapping, replace_newlines: true)
          end

          def mapping
            {
              'Tool' => define_accessor(:report_type),
              'Scanner Name' => define_accessor(:scanner),
              'Status' => define_accessor(:state),
              'Vulnerability' => define_accessor(:title),
              'Details' => define_accessor(:description),
              'Severity' => define_accessor(:severity),
              'CVE' => define_accessor(:cve_value),
              'CWE' => define_accessor(:cwe_value),
              'Other Identifiers' => method(:identifier_formatter),
              'Dismissed At' => define_accessor(:dismissed_at),
              'Dismissed By' => define_accessor(:dismissed_by),
              'Confirmed At' => define_accessor(:confirmed_at),
              'Confirmed By' => define_accessor(:confirmed_by),
              'Resolved At' => define_accessor(:resolved_at),
              'Resolved By' => define_accessor(:resolved_by),
              'Detected At' => define_accessor(:created_at),
              'Location' => define_accessor(:location),
              'Issues' => define_accessor(:related_issues),
              'Merge Requests' => define_accessor(:related_mrs),
              'Activity' => define_accessor(:resolved_on_default_branch),
              'Comments' => define_accessor(:notes_summary),
              'Full Path' => define_accessor(:full_path),
              'CVSS Vectors' => method(:cvss_formatter),
              'Dismissal Reason' => method(:dismissal_formatter),
              'Vulnerability ID' => method(:vulnerability_identifier)
            }
          end

          def define_accessor(attribute)
            proc { |archived_record| archived_record.data[attribute.to_s] }
          end

          def identifier_formatter(archived_record)
            archived_record.data['other_identifiers'].to_csv(col_sep: CSV_DELIMITER, row_sep: '')
          end

          def dismissal_formatter(archived_record)
            archived_record.data['dismissal_reason']&.humanize
          end

          def cvss_formatter(archived_record)
            archived_record.data['cvss'].map { |cvss| "#{cvss['vendor']}=#{cvss['vector']}" }
                        .to_csv(col_sep: CSV_DELIMITER, row_sep: '')
          end

          def vulnerability_identifier(archived_record)
            archived_record.vulnerability_identifier
          end
        end
      end
    end
  end
end
