# frozen_string_literal: true

require 'open3'

module Tooling
  module PredictiveTests
    # The git side of file-based selection: what changed on master since the map's last capture.
    class GitChanges
      def initialize(base_sha:, clickhouse_client:, project_path:, git: method(:run_git))
        @base_sha = base_sha
        @clickhouse_client = clickhouse_client
        @project_path = project_path
        @git = git
      end

      # Files changed on master since the map's last capture. Nil when that can't be worked out.
      def since_last_capture
        captured_sha = last_captured_sha
        return if captured_sha.empty?

        puts "Last capture: #{captured_sha}"
        ensure_commits(captured_sha, base_sha)
        # A capture newer than the MR base already includes what the MR branched from.
        captured_at, base_at = [captured_sha, base_sha].map { |sha| git.call('show', '-s', '--format=%ct', sha).to_i }
        return [] if captured_at >= base_at

        changed = git.call('diff', '--name-only', '--diff-filter=ACMR', "#{captured_sha}..#{base_sha}").split("\n")
        puts "#{changed.size} files changed on master since the last capture"
        changed
      rescue StandardError => e
        puts "Could not compare with the last capture: #{e.message}"
        nil
      end

      # Empty on git errors, so new flags still run the full suite.
      # HEAD holds master's changes, so renames can hide a new flag.
      def added_files
        ensure_commits(base_sha)
        git.call('diff', '--name-only', '--no-renames', '--diff-filter=A', base_sha, 'HEAD').split("\n")
      rescue StandardError => e
        puts "Could not list added files: #{e.message}"
        []
      end

      # Nil on git errors, so the caller runs the full suite.
      def files_naming(word)
        git.call('grep', '-l', '-w', '-F', '-e', word).split("\n")
      rescue StandardError => e
        puts "Could not search for #{word}: #{e.message}"
        nil
      end

      private

      attr_reader :base_sha, :clickhouse_client, :project_path, :git

      # Same query as `last_capture_sha` in scripts/per_test_coverage/select_tests.rb; keep in sync.
      def last_captured_sha
        rows = clickhouse_client.query(<<~SQL, format: 'JSONEachRow')
          SELECT argMax(captured_sha, timestamp) AS sha FROM code_coverage.test_coverage_per_file FINAL
          WHERE ci_project_path = '#{project_path.gsub("'", "''")}'
            AND captured_sha != '' AND test_file NOT LIKE 'qa/%'
        SQL

        rows.dig(0, 'sha').to_s
      end

      # The CI clone is shallow, so a commit may be missing. One commit is enough to compare two trees.
      # Fetch together: fetching a base after its descendant can fail with "bad object".
      def ensure_commits(*shas)
        missing = shas.uniq.reject { |sha| commit?(sha) }
        return if missing.empty?

        git.call('fetch', '--depth=1', 'origin', *missing)
      rescue StandardError => e
        puts "Fetch failed, retrying without telling the server what we have: #{e.message}"
        # Sending no "have" lines stops the server skipping a commit it believes the clone holds.
        git.call('-c', 'fetch.negotiationAlgorithm=noop', 'fetch', '--depth=1', 'origin', *missing)
      end

      def commit?(sha)
        git.call('cat-file', '-e', "#{sha}^{commit}")
        true
      rescue StandardError
        false
      end

      def run_git(*args)
        out, err, status = Open3.capture3('git', *args)
        # `git grep` exits 1 when it finds zero matches.
        return out if args.first == 'grep' && status.exitstatus == 1 && err.empty?
        raise "git #{args.join(' ')} failed: #{err}" unless status.success?

        out
      end
    end
  end
end
