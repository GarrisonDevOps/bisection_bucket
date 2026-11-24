# frozen_string_literal: true

module Vulnerabilities
  module ConsistencyChecks
    # Per-project cooldown between full consistency sweeps.
    #
    # Security-report ingestion runs on every pipeline, and on very active
    # projects (e.g. gitlab-org/gitlab) that means a full-project sweep would be
    # enqueued constantly. The cooldown rate-limits the async sweep checks to at
    # most once per COOLDOWN_PERIOD per project. It is applied inside the
    # Orchestrator, and only to the async checks: synchronous checks
    # (e.g. HasVulnerabilitiesIsCorrectCheck) are cheap single-row reads on the
    # ingestion path and must run every time, not once a day.
    COOLDOWN_PERIOD = 24.hours

    def self.ensure_consistency_on_project!(project)
      return unless Feature.enabled?(:vulnerability_consistency_checks, project, type: :ops)

      Orchestrator.new(project).execute
    end

    def self.cooldown_key(project)
      "vulnerability_consistency_check:last_run:#{project.id}"
    end
  end
end
