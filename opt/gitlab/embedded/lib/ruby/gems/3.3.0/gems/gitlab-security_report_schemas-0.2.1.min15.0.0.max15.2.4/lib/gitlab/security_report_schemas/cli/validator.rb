# frozen_string_literal: true

require "optparse"
require_relative "../utils/string_refinements"

module Gitlab
  module SecurityReportSchemas
    module CLI
      # Validation command line interface
      class Validator
        using Utils::StringRefinements

        def initialize(argv)
          @argv = argv
        end

        def run
          configure

          run_validation
          print_warnings
        end

        private

        attr_reader :argv, :warnings

        def file_path
          @file_path ||= argv.shift
        end

        def configure
          opt_parser.parse!(argv)

          exit_with_usage_message unless file_path
          exit_with_unknown_report_type_message unless report_type
        rescue OptionParser::InvalidOption => e
          exit_with_usage_message(e.message)
        end

        def exit_with_usage_message(extra_message = nil)
          puts extra_message if extra_message
          puts opt_parser.help

          exit
        end

        def exit_with_unknown_report_type_message
          puts "Can not find report type! Consider providing the report type."

          exit
        end

        def run_validation
          puts "Validating #{report_type} v#{version} against schema v#{validator.schema_ver_version}"

          if validator.valid?
            puts "Content is valid".green
          else
            puts "Content is invalid".red
            puts make_string(validator.errors)
          end
        end

        def print_warnings
          return unless warnings && validator.warnings.present?

          puts make_string(validator.warnings).brown
        end

        def make_string(array)
          array.map { |message| "* #{message}" }
               .join("\n")
        end

        def validator
          @validator ||= SecurityReportSchemas::Validator.new(report_data, report_type, version)
        end

        def version
          report_data["version"]
        end

        def report_type
          @report_type ||= report_data.dig("scan", "type")
        end

        def report_data
          @report_data ||= JSON.parse(report_content)
        end

        def report_content
          File.read(file_path)
        end

        def opt_parser
          @opt_parser ||= OptionParser.new do |parser|
            parser.banner = banner_message

            parser.on("-r", "--report_type=REPORT_TYPE", "Override the report type") do |arg|
              @report_type = arg
            end

            parser.on("-w", "--warnings", "Prints the warning messages") do
              @warnings = true
            end
          end
        end

        def banner_message
          "SecurityReportSchemas #{SecurityReportSchemas::Version}.\n" \
          "Supported schema versions: #{supported_versions.to_s.green}\n\n" \
          "Usage: security-report-schemas REPORT_FILE_PATH [options]"
        end

        def supported_versions
          SecurityReportSchemas.supported_versions.map(&:version)
        end
      end
    end
  end
end
