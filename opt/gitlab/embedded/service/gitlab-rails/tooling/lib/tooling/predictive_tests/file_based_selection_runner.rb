# frozen_string_literal: true

require 'json'
require 'gitlab_quality/test_tooling'

require_relative '../find_changes'
require_relative 'file_based_selector'
require_relative 'git_changes'
require_relative '../../../quality/test_level'

module Tooling
  module PredictiveTests
    # Prints the rspec files the ClickHouse coverage map would select for this merge request, and how many.
    # It does not run them.
    class FileBasedSelectionRunner
      OUTPUT_FILE = 'file_based_selection.json'
      TABLE_NAME = 'file_based_selection_runs'

      def initialize(clickhouse_client: nil)
        @clickhouse_client = clickhouse_client
      end

      def execute
        puts "Changed files: #{changed_files.size}"
        write_artifact
        record_run
        print_selection
      end

      private

      def result
        @result ||= FileBasedSelector.new(
          changed_files: changed_files,
          recent_changed_files: git_changes.since_last_capture,
          added_files: git_changes.added_files,
          flag_users: git_changes.method(:files_naming),
          clickhouse_client: clickhouse_client,
          project_path: project_path
        ).execute
      end

      def changed_files
        @changed_files ||= Tooling::FindChanges.new(from: :api).execute
      end

      def git_changes
        GitChanges.new(base_sha: base_sha, clickhouse_client: clickhouse_client, project_path: project_path)
      end

      # rubocop:disable Gitlab/Json -- standalone script, the app is not loaded
      def write_artifact
        File.write(OUTPUT_FILE, JSON.pretty_generate(
          full_suite_reason: result.full_suite_reason, specs: result.specs, changed_files: changed_files
        ))
      end
      # rubocop:enable Gitlab/Json

      def record_run
        clickhouse_client.insert_json_data(TABLE_NAME, [run_row])
      rescue StandardError => e
        warn "Warning: failed to record run in ClickHouse: #{e.message}"
      end

      def run_row
        {
          timestamp: Time.now.utc.strftime('%Y-%m-%d %H:%M:%S.%6N'),
          ci_project_path: project_path,
          ci_pipeline_id: ENV.fetch('CI_PIPELINE_ID').to_i,
          ci_job_id: ENV.fetch('CI_JOB_ID').to_i,
          ci_merge_request_iid: ENV.fetch('CI_MERGE_REQUEST_IID').to_i,
          head_sha: head_sha,
          base_sha: base_sha,
          full_suite_reason: result.full_suite_reason.to_s,
          changed_files: changed_files,
          selected_specs: result.specs.to_a
        }
      end

      def print_selection
        if result.full_suite_reason
          puts "Would run the full suite: #{result.full_suite_reason}"
          return
        end

        puts "Selected #{result.specs.size} rspec files:"
        puts result.specs

        test_level = Quality::TestLevel.new(['', 'ee/', 'jh/'])
        levels = result.specs.map { |spec| test_level.level_for(spec) }.tally
        puts "By test level: #{levels.map { |level, count| "#{level} #{count}" }.join(', ')}"
      end

      def clickhouse_client
        @clickhouse_client ||= GitlabQuality::TestTooling::ClickHouse::Client.new(
          url: ENV.fetch('GLCI_DA_CLICKHOUSE_URL'),
          database: ENV.fetch('GLCI_CLICKHOUSE_CODE_COVERAGE_DB'),
          username: ENV.fetch('GLCI_CLICKHOUSE_METRICS_USERNAME'),
          password: ENV.fetch('GLCI_CLICKHOUSE_METRICS_PASSWORD')
        )
      end

      def project_path
        ENV.fetch('CI_PROJECT_PATH')
      end

      def head_sha
        source_sha = ENV.fetch('CI_MERGE_REQUEST_SOURCE_BRANCH_SHA', '')
        source_sha.empty? ? ENV.fetch('CI_COMMIT_SHA') : source_sha
      end

      def base_sha
        ENV.fetch('CI_MERGE_REQUEST_DIFF_BASE_SHA')
      end
    end
  end
end
