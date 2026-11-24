# frozen_string_literal: true

module Gitlab
  module Geo
    # SPIKE (gitlab-org/gitlab#602803): console/CLI entry point over the Geo known-error
    # catalog. The geo:tools rake tasks are thin wrappers around these methods, so the same
    # checks can be run from a Rails console without invoking rake (mirrors
    # Gitlab::Geo::GeoTasks).
    module Tools
      extend self

      class UnsupportedFormatError < StandardError
        def initialize(output_format)
          super("Unsupported format: #{output_format}")
        end
      end

      SUPPORTED_FORMATS = [
        :text,
        :json
      ].freeze

      # Read-only: scan the catalog and print any detected known errors with a suggested fix.
      # Pass a single known error to check only that one, for example when a scan of the whole
      # catalog is more work than an operator needs. With output_format: :json, nothing but the JSON
      # document reaches stdout, so a caller can pipe straight into a parser.
      def cleanup_check(known_error = nil, output_format: :text, **options)
        output_format = output_format.to_s.downcase.to_sym
        raise UnsupportedFormatError, output_format unless SUPPORTED_FORMATS.include?(output_format)

        report = ::Geo::Tools::CleanupCheckReport.new(
          detected_errors(known_error, **options),
          scanned_for: known_error&.name
        )

        if output_format == :json
          puts report.to_pretty_json
        else
          puts report.text_header, report
        end
      end

      # Resolve a known error. Dry run by default; the destructive strategies only act when
      # dry_run is false. Prints a header, the dry-run sample, and the service result.
      def resolve(known_error, dry_run: true, limit: nil)
        puts "Resolving Geo error: #{known_error.title} (dry run mode #{dry_run ? 'ON' : 'OFF'})"
        puts

        if dry_run
          sample = known_error.sample
          puts "Sample of affected records (up to #{sample.size}):"
          sample.each { |line| puts "  #{line}" }
          puts
        end

        response = ::Geo::Tools::ResolveKnownErrorService.new(known_error, dry_run: dry_run, limit: limit).execute
        puts response.message

        response
      end

      private

      def detected_errors(known_error, **options)
        proc { Array.wrap(known_error || ::Geo::Tools::KnownErrors.catalog(**options)).select(&:detected?) }
      end
    end
  end
end
