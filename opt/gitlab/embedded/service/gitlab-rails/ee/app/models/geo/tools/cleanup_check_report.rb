# frozen_string_literal: true

module Geo
  module Tools
    # SPIKE (gitlab-org/gitlab#602803): renders one cleanup_check detection pass. Both output
    # formats are derived from the same data, so text and JSON cannot drift apart.
    class CleanupCheckReport
      def initialize(detected_errors, scanned_for: nil)
        @detected_errors = detected_errors
        @scanned_for = scanned_for
      end

      def to_s
        lines = [
          ''
        ]

        if results.empty?
          lines << 'No known issues detected.'
        else
          results.each_with_index do |known_error, index|
            lines.concat(error_lines(known_error, index))
          end
        end

        lines << 'Add DRY_RUN=false to a resolve task to actually apply it.'

        lines.join("\n")
      end

      def to_h
        {
          scanned_for: scanned_for,
          scanned_on: scanned_on,
          detected_errors: results.map(&:to_h)
        }
      end

      def to_pretty_json
        ::Gitlab::Json.pretty_generate(to_h)
      end

      def text_header
        [
          "Geo Cleanup Check -- #{scanned_on.capitalize} Site",
          '=' * 40,
          "Scanning for #{scanned_for ? "'#{scanned_for}'" : 'known issues'}..."
        ]
      end

      private

      attr_reader :detected_errors, :scanned_for

      def results
        return @results unless @results.nil?

        @results = detected_errors.call
      end

      # Role of the node that ran the scan. Deliberately not called "site": a catalog entry
      # has its own site, meaning the node its resolve has to run on, which can differ.
      def scanned_on
        ::Gitlab::Geo.primary? ? 'primary' : 'secondary'
      end

      def error_lines(known_error, index)
        [
          "#{index + 1}. #{known_error.title} (#{known_error.severity})",
          count_line(known_error),
          action_line(known_error),
          ''
        ]
      end

      def count_line(known_error)
        if known_error.match_pattern.present?
          "   #{known_error.affected_count_label} records matching '#{known_error.match_pattern}'"
        else
          "   #{known_error.affected_count_label} records affected (structural check)"
        end
      end

      def action_line(known_error)
        if known_error.resolvable
          "   -> Run: sudo gitlab-rake \"geo:tools:resolve[#{known_error.name}]\" (dry run by default)"
        else
          "   -> Manual intervention required. Docs: #{known_error.docs}"
        end
      end
    end
  end
end
