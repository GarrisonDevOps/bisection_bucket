# frozen_string_literal: true

module Security
  module ScanProfiles
    class Configuration
      module Defaults
        module TriageAndRemediation
          STANDARD = {
            vulnerability_enrichment: { severity_level: 'medium', run_mode: 'auto' },
            sast_vulnerability_resolution: {
              severity_level: 'medium', run_mode: 'auto', open_merge_requests_limit: 15
            },
            sast_false_positive: { severity_level: 'medium', run_mode: 'auto' },
            secret_detection_false_positive: { severity_level: 'medium', run_mode: 'auto' },
            sbom_ingested: DependencyScanningPostProcessing::VALUES
          }.freeze

          CONSERVATIVE = {
            vulnerability_enrichment: { severity_level: 'high', run_mode: 'auto' },
            sast_vulnerability_resolution: {
              severity_level: 'high', run_mode: 'manual', open_merge_requests_limit: 5
            },
            sast_false_positive: { severity_level: 'high', run_mode: 'manual' },
            secret_detection_false_positive: { severity_level: 'high', run_mode: 'manual' },
            sbom_ingested: {
              auto_remediation: {
                cooldown: 7,
                severity_level: 'high',
                upgrade_policy: 'minor',
                open_merge_requests_limit: 5
              }
            }
          }.freeze

          PROACTIVE = {
            vulnerability_enrichment: { severity_level: 'info', run_mode: 'auto' },
            sast_vulnerability_resolution: {
              severity_level: 'info', run_mode: 'auto', open_merge_requests_limit: nil
            },
            sast_false_positive: { severity_level: 'info', run_mode: 'auto' },
            secret_detection_false_positive: { severity_level: 'info', run_mode: 'auto' },
            sbom_ingested: {
              auto_remediation: {
                cooldown: 7,
                severity_level: 'info',
                upgrade_policy: 'major'
              }
            }
          }.freeze

          PRESETS = {
            conservative: CONSERVATIVE,
            standard: STANDARD,
            proactive: PROACTIVE
          }.freeze
        end
      end
    end
  end
end
