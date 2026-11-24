# frozen_string_literal: true

module Analytics
  module Orbit
    class JobFailure
      SCAN_LINES = 2000
      FULL_SCAN_LINES = 5000
      LOG_BYTES = 6_000
      FULL_LOG_BYTES = 40_000
      LINE_CHARS = 500
      FOLD_RUN = 5
      AFTER_SCRIPT = 'after-script'
      AFTER_SCRIPT_SHARE = 4
      GAP = '...'
      MAX_TESTS = 20
      OUTPUT_LINES = 10
      # Runner sections around the job script. Lines in any other section are script output, and so are
      # lines in none when the scanned window starts mid-log, because their section start was cut off.
      RUNNER_SECTIONS = %w[
        prepare-executor prepare-script resolve-secrets get-sources clear-worktree restore-cache
        download-artifacts archive-cache archive-cache-on-failure upload-artifacts-on-success
        upload-artifacts-on-failure cleanup-file-variables
      ].freeze

      def initialize(job, user, read_log: true, read_tests: true, full_log: false)
        @job = job
        @user = user
        @read_log = read_log
        @read_tests = read_tests
        @full_log = full_log
      end

      def execute
        truncated = []
        { failed_tests: failed_tests(truncated), log: log_text(truncated), truncated: truncated.presence }.compact
      end

      private

      attr_reader :job, :user, :read_log, :read_tests, :full_log

      def failed_tests(truncated)
        return unless read_tests && job.has_test_reports? && job.test_report_readable_by?(user)

        report = job.collect_test_reports!(::Gitlab::Ci::Reports::TestReport.new)
        tests = report.test_suites.values.flat_map { |suite| suite.failed.values + suite.error.values }
        truncated << :failed_tests if tests.size > MAX_TESTS
        tests.first(MAX_TESTS).map { |test| test_summary(test) }.presence
      end

      def test_summary(test)
        {
          name: test.name,
          classname: test.classname,
          file: test.file,
          output: test.system_output.to_s.strip.lines.first(OUTPUT_LINES).join.rstrip.presence
        }.compact
      end

      def log_text(truncated)
        return unless readable_log?

        scan = full_log ? FULL_SCAN_LINES : SCAN_LINES
        raw = job.trace.raw(last_lines: scan).to_s
        cut = raw.lines.size >= scan
        budget = full_log ? FULL_LOG_BYTES : LOG_BYTES
        script, after = split_after_script(script_lines(raw, cut))
        after_tail, after_cut, after_over = tail_of(after, budget / AFTER_SCRIPT_SHARE)
        script_tail, script_cut, script_over = tail_of(script, budget - bytes(after_tail))
        truncated << :log if full_log && (cut || script_over || after_over)
        [*(GAP if cut || script_cut), *script_tail, *(GAP if after_cut), *after_tail].join("\n").presence
      end

      def readable_log?
        read_log && job.has_trace? && Ability.allowed?(user, :read_build_trace, job)
      end

      def script_lines(raw, cut)
        lines = ::Gitlab::Ci::Ansi2json.convert(StringIO.new(raw)).lines.reject { |line| line[:section_header] }
        script = lines.select { |line| script_output?(line[:section], cut) }
        script = lines if script.empty?
        script.map { |line| [line[:section], line[:content].sum('') { |segment| segment[:text] }.rstrip] }
          .reject { |_, text| text.blank? }
      end

      def split_after_script(lines)
        lines.partition { |section, _| section != AFTER_SCRIPT }.map { |part| part.map { |_, text| clip(text) } }
      end

      def tail_of(lines, budget)
        over = bytes(lines) > budget
        lines = fold(lines) if over
        tail = within_budget(lines, budget)
        [tail, tail.size < lines.size, over]
      end

      def bytes(lines)
        lines.sum { |line| line.bytesize + 1 }
      end

      def fold(lines)
        lines.slice_when { |a, b| shape(a) != shape(b) }.flat_map do |run|
          next run if run.size < FOLD_RUN

          [run.first, "#{GAP} (#{run.size - 2} similar lines)", run.last]
        end
      end

      def shape(line)
        line.gsub(/\h{7,}|\d+/, '#')
      end

      def clip(line)
        line.length > LINE_CHARS ? "#{line[0, LINE_CHARS]}#{GAP}" : line
      end

      def within_budget(lines, bytes)
        used = 0
        lines.reverse.take_while { |line| (used += line.bytesize + 1) <= bytes }.reverse
      end

      def script_output?(section, cut)
        section ? RUNNER_SECTIONS.exclude?(section) : cut
      end
    end
  end
end
