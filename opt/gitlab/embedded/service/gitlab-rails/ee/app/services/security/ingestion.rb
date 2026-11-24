# frozen_string_literal: true

module Security
  module Ingestion
    def self.ingest_pipeline?(pipeline)
      return true if pipeline.default_branch?
      return true if Security::AgenticAnalyzer.default_branch_scan?(pipeline)
      return false unless Security::VAC.enabled?(pipeline.project)

      Security::ProjectTrackedContext.tracked_pipeline?(pipeline)
    end
  end
end
