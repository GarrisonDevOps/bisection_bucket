# frozen_string_literal: true

module Tasks
  module CloudConnector
    module TaskHelper
      COLORS = {
        success: :green,
        failure: :red,
        details: :black,
        check: :blue,
        warning: :yellow
      }.freeze
      USER_NOT_PROVIDED_MESSAGE = "User not provided"
      SKIPPING_MESSAGE_TEXT = "\n• Skipping %{name} check: %{message}"
      USAGE_TEXT = "\n  Usage: rake 'cloud_connector:health_check[username,report.json]'"
      SKIPPING_CHECKS_TEXT = "\n  Please note that some checks might fail or be skipped, " \
        "if a valid username is not provided."
      PLEASE_PROVIDE_FILENAME_TEXT = "\n  If you want to save report to a file, " \
        "please specify the filename when running the task. #{USAGE_TEXT}".freeze
      PLEASE_PROVIDE_USER_TEXT = "Proceeding without a user... #{SKIPPING_CHECKS_TEXT} #{USAGE_TEXT}".freeze
      OUTPUT_DIR = Rails.root.join('tmp/cloud_connector/reports')

      class << self
        def find_user(username)
          unless username
            log_warning("The username was not provided. #{PLEASE_PROVIDE_USER_TEXT}")

            return
          end

          user = User.find_by_username(username)
          log_warning("User '#{username}' not found. #{PLEASE_PROVIDE_USER_TEXT}") unless user

          user
        end

        def save_report(filename, probe_results)
          return log(PLEASE_PROVIDE_FILENAME_TEXT) unless filename

          report_path = File.join(OUTPUT_DIR, File.basename(filename))

          log("\n• Saving report to #{report_path}...", color: COLORS[:check])

          begin
            FileUtils.mkdir_p(OUTPUT_DIR)

            File.open(report_path, 'w') do |file|
              file.write(pretty_json(probe_results.as_json))
            end

            print_success("Report successfully written to #{report_path}")
          rescue StandardError => e
            print_failure("Failed to write report to #{report_path}: #{e.message}")
          end
        end

        def process_probe_results(probe_results, include_details: false)
          probe_results.each do |result|
            log("\n• #{result.name.to_s.humanize} check...", color: COLORS[:check])

            print_details(result.details) if include_details && result.details.present?

            if result.success?
              print_success(result.message)
            else
              process_errors(result)
            end
          end
        end

        def pretty_json(data)
          ::Gitlab::Json.pretty_generate(data).gsub(/^/, '    ')
        end

        private

        def process_errors(result)
          return print_failure(result.message) unless result.errors.present?

          result.errors.full_messages.each do |error|
            if error.include?(USER_NOT_PROVIDED_MESSAGE)
              log(skipping_message(result.name, error))
            else
              print_failure(error)
            end
          end
        end

        def skipping_message(name, message)
          format(SKIPPING_MESSAGE_TEXT, name: name.to_s.humanize, message: message)
        end

        def print_success(message)
          log("#{colored_message('✔ Success:', COLORS[:success])} #{message}")
        end

        def print_failure(message)
          log("#{colored_message('✖ Failure:', COLORS[:failure])} #{message}")
        end

        def print_details(details)
          log('  ◦ Details:', color: COLORS[:details])
          log(pretty_json(details.as_json))
        end

        def log(message, color: nil)
          $stdout.puts color ? colored_message(message, color) : message
        end

        def log_warning(message)
          log("\n⚠ Warning: #{message}", color: COLORS[:warning])
        end

        def colored_message(message, color)
          Rainbow.new.wrap(message).color(color).bright
        end
      end
    end
  end
end
