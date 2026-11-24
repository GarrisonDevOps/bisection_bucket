# frozen_string_literal: true

module EE
  module Releases
    module EvidenceSizeLimit
      extend ::Gitlab::Utils::Override

      # One `{"url": ...}` entry per report job of the evidence pipeline
      REPORT_ARTIFACT_BYTES = 200

      private

      override :report_artifacts_bytes
      def report_artifacts_bytes
        return 0 unless pipeline && release.project.licensed_feature_available?(:release_evidence_test_artifacts)

        pipeline.latest_report_builds.count * REPORT_ARTIFACT_BYTES
      end
    end
  end
end
