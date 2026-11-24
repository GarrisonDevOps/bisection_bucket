# frozen_string_literal: true

module Security
  module SecurityOrchestrationPolicies
    class ObserveHistogramsService
      HISTOGRAMS = {
        gitlab_security_policies_scan_execution_configuration_rendering_seconds: {
          description: 'The amount of time to render scan execution policy CI configurations',
          buckets: [1, 3, 5, 10].freeze
        },
        gitlab_security_policies_scan_result_process_duration_seconds: {
          description: 'The amount of time to process scan result policies',
          buckets: [120, 240, 360, 480, 600, 720, 840, 960].freeze
        },
        gitlab_security_policies_update_configuration_duration_seconds: {
          description: 'The amount of time to schedule sync for a policy configuration change',
          buckets: [5, 120, 600].freeze
        },
        gitlab_security_policies_policy_sync_duration_seconds: {
          description: 'The amount of time to sync policy changes for a policy configuration',
          buckets: [1, 3, 5, 10, 20, 50].freeze
        },
        gitlab_security_policies_policy_deletion_duration_seconds: {
          description: 'The amount of time to delete policy-related configuration',
          buckets: [5, 20, 40, 80, 120, 240].freeze
        },
        gitlab_security_policies_policy_creation_duration_seconds: {
          description: 'The amount of time to create policy-related configuration',
          buckets: [1, 3, 5, 10, 20, 50].freeze
        },
        gitlab_security_policies_sync_opened_merge_requests_duration_seconds: {
          description: 'The amount of time to sync opened merge requests after policy changes',
          buckets: [5, 10, 20, 40, 80, 120, 240, 360].freeze
        },
        gitlab_security_policies_pipeline_execution_policy_scheduling_duration_seconds: {
          description: 'The amount of time to schedule due pipeline execution policy project schedules',
          buckets: [5, 15, 30, 60, 120, 180, 300].freeze
        },
        gitlab_security_policies_pipeline_execution_policy_dry_run_pipeline: {
          description: 'The amount of time to dry-run single pipeline execution policy pipelines',
          buckets: [1, 2, 4, 8, 15, 25, 35, 45, 55, 60].freeze
        },
        gitlab_security_policies_pipeline_execution_policy_build_policy_pipelines: {
          description: 'The amount of time to build all pipeline execution policy pipelines',
          buckets: [10, 30, 60, 120, 180, 300, 600].freeze
        },
        gitlab_security_policies_vulnerability_management_auto_dismiss: {
          description: 'The amount of time to evaluate auto-dismiss policies',
          buckets: [1, 3, 5, 10, 20, 50].freeze
        },
        gitlab_security_policies_vulnerability_management_auto_severity_override: {
          description: 'The amount of time to evaluate auto-severity-override policies',
          buckets: [1, 3, 5, 10, 20, 50].freeze
        }
      }.freeze

      class << self
        def measure(name, labels: {}, callback: nil)
          lo = ::Gitlab::Metrics::System.monotonic_time
          ret_val = yield
          hi = ::Gitlab::Metrics::System.monotonic_time
          duration = hi - lo

          histogram(name).observe(labels, duration)

          callback&.call(duration)

          ret_val
        end

        def histogram(name)
          histograms[name] ||= begin
            config = HISTOGRAMS[name] || raise(ArgumentError, "unsupported histogram: #{name}")

            Gitlab::Metrics.histogram(name, config[:description], {}, config[:buckets])
          end
        end

        def histograms
          @histograms ||= {}
        end
      end
    end
  end
end
