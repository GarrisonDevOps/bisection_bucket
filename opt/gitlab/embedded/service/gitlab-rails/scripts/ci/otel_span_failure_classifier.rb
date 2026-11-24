# frozen_string_literal: true

require 'json'

# Classifies observed tool results, not infrastructure root causes or test flakiness.
class OtelSpanFailureClassifier
  MAX_REPORT_BYTES = 8 * 1024 * 1024
  MAX_REPORTS = 64

  # Categories are `<namespace>:<name>`. `platform:` is reserved for GitLab product code,
  # so values emitted by these CI scripts use `user:`.
  CATEGORY_TEST_FAILURE = 'user:test:failure'
  CATEGORY_TEST_FRAMEWORK_ERROR = 'user:test:framework_error'
  CATEGORY_UNKNOWN = 'user:unknown'

  def self.attributes(span)
    return {} if span.exit_code == 0

    category = rspec_category(span)
    {
      'gitlab.cicd.failure.category' => category || CATEGORY_UNKNOWN,
      'gitlab.cicd.failure.source' => category ? 'rspec_report' : 'exit_code'
    }
  rescue StandardError
    { 'gitlab.cicd.failure.category' => CATEGORY_UNKNOWN, 'gitlab.cicd.failure.source' => 'exit_code' }
  end

  def self.rspec_category(span)
    return unless span.operation_kind == 'test' && [1, 2].include?(span.exit_code)
    return if span.rspec_report.to_s.empty?

    failures, errors = report_counts(span)

    # Mixed failures retain the outside-example error rather than claiming only test failures.
    return CATEGORY_TEST_FRAMEWORK_ERROR if errors > 0 && (span.exit_code == 2 || span.operation_name == 'e2e')
    return CATEGORY_TEST_FAILURE if span.exit_code == 1 && failures > 0 && errors == 0

    nil
  end

  def self.report_counts(span)
    paths = report_paths(span)
    counts = paths.map do |path|
      summary = read_summary(span, path, MAX_REPORT_BYTES / paths.size)
      [summary.fetch('failure_count'), summary.fetch('errors_outside_of_examples_count')]
    end
    raise ArgumentError unless counts.flatten.all? { |value| value.is_a?(Integer) && value >= 0 }

    [counts.sum(&:first), counts.sum(&:last)]
  end

  def self.report_paths(span)
    count = Integer(span.rspec_report_count || '1', 10)
    raise ArgumentError unless count.between?(1, MAX_REPORTS)

    worker_reports = span.rspec_report.include?('%{worker}')
    return [span.rspec_report] if count == 1 && !worker_reports

    raise ArgumentError unless worker_reports

    (1..count).map { |worker| span.rspec_report.gsub('%{worker}', worker.to_s) }
  end

  def self.read_summary(span, path, limit)
    File.open(path, File::RDONLY | File::NONBLOCK) do |file|
      stat = file.stat
      next {} unless stat.file? && stat.size <= limit
      next {} if stat.mtime.to_r * 1_000_000_000 < span.start_time_ns

      content = file.read(limit + 1)
      next {} if content.bytesize > limit

      JSON.parse(content).fetch('summary')
    end
  end
  private_class_method :rspec_category, :report_counts, :report_paths, :read_summary
end
