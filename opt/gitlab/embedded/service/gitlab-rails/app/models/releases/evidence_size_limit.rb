# frozen_string_literal: true

module Releases
  # Measures the parts of a release evidence that users see without loading them, and fits issues into the rest.
  class EvidenceSizeLimit
    # Keys, punctuation and short values each serialized record adds besides its measured text
    RECORD_OVERHEAD_BYTES = 200
    ISSUE_BATCH_SIZE = 100

    def initialize(release, pipeline: nil)
      @release = release
      @pipeline = pipeline
    end

    def enabled?
      limit_bytes > 0 && Feature.enabled?(:release_evidence_size_limit, release.project)
    end

    def exceeded?
      enabled? && served_bytes > limit_bytes
    end

    # Bytes left for the issues, which the evidence stores but never serves
    def remaining_bytes
      [limit_bytes - served_bytes, 0].max
    end

    # Issues per milestone ID that fit in the remaining bytes. We drop issue descriptions before whole issues,
    # and read issues only until the bytes are spent.
    def milestone_issues
      budget = remaining_bytes
      issues_by_milestone = release.milestones.ids.index_with { [] }

      issues_by_milestone.each do |milestone_id, issues|
        budget = append_issues_within(budget, milestone_id, issues)
      end

      add_descriptions_within(budget, issues_by_milestone.values.flatten)

      issues_by_milestone
    end

    def limit_bytes
      Gitlab::CurrentSettings.release_evidence_max_size_bytes
    end

    def served_bytes
      @served_bytes ||= release_bytes + project_bytes + milestones_bytes + packages_bytes + report_artifacts_bytes
    end

    def error_message
      format(
        _('The release evidence would exceed the maximum size of %{limit} set for this instance. ' \
          'Ask an administrator to increase the release evidence size limit.'),
        limit: ActiveSupport::NumberHelper.number_to_human_size(limit_bytes)
      )
    end

    def warning_message
      format(
        _('No evidence was collected for this release. %{error} ' \
          'After the limit is increased, collect the evidence with the release evidence API.'),
        error: error_message
      )
    end

    def upcoming_release_warning_message
      format(
        _('Evidence will not be collected on the release date if this release still exceeds the limit then. ' \
          '%{error} After the limit is increased, collect the evidence with the release evidence API.'),
        error: error_message
      )
    end

    private

    attr_reader :release, :pipeline

    def release_bytes
      Release.id_in(release.id).pick(Arel.sql(json_bytes(:name, :description, :tag))).to_i + RECORD_OVERHEAD_BYTES
    end

    def project_bytes
      Project.id_in(release.project_id).pick(Arel.sql(json_bytes(:name, :description))).to_i + RECORD_OVERHEAD_BYTES
    end

    def milestones_bytes
      count, bytes = release.milestones.pick(Arel.sql('COUNT(*)'), Arel.sql("SUM(#{json_bytes(:title, :description)})"))

      bytes.to_i + (count.to_i * RECORD_OVERHEAD_BYTES)
    end

    def packages_bytes
      packages = release.tagged_packages.select(:name, :version).limit(max_measured_packages)
      count, bytes = ::Packages::Package.from(packages, :packages_packages)
        .pick(Arel.sql('COUNT(*)'), Arel.sql("SUM(#{json_bytes(:name, :version)})"))

      bytes.to_i + (count.to_i * RECORD_OVERHEAD_BYTES)
    end

    # Their overhead alone puts this many packages over the limit, so we read no more
    def max_measured_packages
      (limit_bytes / RECORD_OVERHEAD_BYTES) + 1
    end

    # Overridden in EE, which serves report artifacts
    def report_artifacts_bytes
      0
    end

    def append_issues_within(budget, milestone_id, issues)
      last_id = 0

      loop do
        batch = issues_without_description(milestone_id, last_id).to_a

        batch.each do |issue|
          bytes = issue_json_bytes(issue)
          return budget if bytes > budget

          issues << issue
          budget -= bytes
        end

        return budget if batch.size < ISSUE_BATCH_SIZE

        last_id = batch.last.id
      end
    end

    def add_descriptions_within(budget, issues)
      fitting = issues.select do |issue|
        bytes = issue.description_json_bytes
        next false if bytes == 0 || bytes > budget

        budget -= bytes
        true
      end

      fitting.each_slice(ISSUE_BATCH_SIZE) do |batch|
        descriptions = Issue.id_in(batch.map(&:id)).limit(batch.size).pluck(:id, :description).to_h

        batch.each { |issue| issue.description = descriptions[issue.id] }
      end
    end

    def issues_without_description(milestone_id, last_id)
      Issue
        .where(milestone_id: milestone_id)
        .where(Issue.arel_table[:id].gt(last_id))
        .select(*(Issue.column_names - %w[description description_html]))
        .select('NULL::text AS description')
        .select("#{json_bytes('issues.description')} AS description_json_bytes")
        .order(:id)
        .limit(ISSUE_BATCH_SIZE)
    end

    def issue_json_bytes(issue)
      # One more byte for the comma between issues
      Gitlab::Json.generate(Evidences::IssueEntity.represent(issue).as_json).bytesize + 1
    end

    # Bytes of each text plus its quotes, read from the column header without loading
    # the text. The stored jsonb holds text unescaped, so we don't count JSON escapes.
    def json_bytes(*columns)
      columns.map { |column| "COALESCE(OCTET_LENGTH(#{column}) + 2, 0)" }.join(' + ')
    end
  end
end

Releases::EvidenceSizeLimit.prepend_mod_with('Releases::EvidenceSizeLimit')
