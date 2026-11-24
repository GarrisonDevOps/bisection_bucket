# frozen_string_literal: true

module DependencyManagement
  module SecurityUpdate
    class SchedulerService < BaseService
      include Gitlab::Utils::StrongMemoize
      include Gitlab::InternalEventsTracking

      # Auto Remediation is only supported for a limited set of package managers.
      SUPPORTED_PACKAGE_MANAGERS = Eligibility::SUPPORTED_PACKAGE_MANAGERS

      # These MUST stay sorted, so that we don't have to sort using Postgres.
      # Doing so is expensive, and we cannot add another index on the sbom_occurrences
      # table.
      SORTED_SEVERITY_LEVELS = %i[critical high medium low].freeze

      RUN_RATE_LIMIT_KEY = :dependency_management_scheduler_run
      RESCHEDULE_RATE_LIMIT_KEY = :dependency_management_scheduler_reschedule

      private_constant :SUPPORTED_PACKAGE_MANAGERS,
        :SORTED_SEVERITY_LEVELS,
        :RUN_RATE_LIMIT_KEY,
        :RESCHEDULE_RATE_LIMIT_KEY

      def self.execute(...)
        new(...).execute
      end

      def initialize(project:, skip_dismissed_branches: false)
        super(project: project)

        @skip_dismissed_branches = skip_dismissed_branches
      end

      def execute
        return unless project && remediation_profile
        return if run_throttled?

        # The lookup does not provision. With no account yet, UpdateService provisions it and checks.
        account = project.dependency_management_service_account
        return if account && merge_request_denial(account)

        self.remediation_count = open_remediations.size
        refresh_open_remediations!

        SUPPORTED_PACKAGE_MANAGERS.each do |package_manager|
          break if scan_finished?

          execute_for_package_manager(package_manager)
        end
      end

      private

      attr_accessor :remediation_count, :repository_config_invalid, :merge_requests_denied
      attr_reader :skip_dismissed_branches

      def run_throttled?
        return false unless Feature.enabled?(:dependency_management_scheduler_rate_limit, project)

        key = skip_dismissed_branches ? RESCHEDULE_RATE_LIMIT_KEY : RUN_RATE_LIMIT_KEY
        return false unless ::Gitlab::ApplicationRateLimiter.throttled?(key, scope: { project: project })

        Gitlab::AppLogger.info(
          build_structured_payload_labkit(
            message: 'DependencyManagement: scheduler run throttled',
            Labkit::Fields::GL_PROJECT_ID => project.id,
            rate_limit_key: key
          )
        )

        true
      end

      # Open remediation MRs keyed by source branch, fetched once. The branch set decides
      # which occurrences are already covered by an open MR, and the records themselves are
      # refreshed directly in refresh_open_remediations! Bounded by open_merge_requests_limit,
      # so a handful of rows - cheaper than re-querying per branch during the scan.
      def open_remediations
        return {} unless project

        DependencyManagement::SecurityUpdate::OpenRemediationsFinder
          .new(project: project)
          .execute
          .index_by(&:source_branch)
      end
      strong_memoize_attr :open_remediations

      def user_closed_remediations_finder
        DependencyManagement::SecurityUpdate::UserClosedRemediationsFinder.new(project: project)
      end
      strong_memoize_attr :user_closed_remediations_finder

      def execute_for_package_manager(package_manager)
        severity_levels.each do |severity_level|
          break if scan_finished?

          execute_for_package_manager_and_severity_level(package_manager, severity_level)
        end
      end

      def execute_for_package_manager_and_severity_level(package_manager, severity_level)
        finder = DependencyManagement::SecurityUpdate::VulnerableSbomOccurrencesFinder.new(
          project: project,
          package_manager: package_manager,
          severity_level: severity_level
        )

        finder.execute_in_batches do |occurrences|
          # Leaving only the inner loop would still fetch every remaining batch.
          break if scan_finished?

          occurrences.each do |occurrence|
            break if scan_finished?

            schedule_remediation(occurrence)
          end
        end
      end

      # An invalid repository config fails every remediation on the project the
      # same way, and a failure never counts toward the limit, so without this
      # the scan would run every occurrence through UpdateService. A denial
      # likewise holds for every occurrence.
      def scan_finished?
        repository_config_invalid || merge_requests_denied || merge_request_limit_reached?
      end

      def merge_request_limit_reached?
        # WARNING: We should be careful here. If this limit is ever configured,
        # we can end up in a situation where we have more merge requests
        # open than the limit. If that happens and we do a strict check
        # then we'll continue to open merge requests. This limit will
        # be configurable by the customer, so we need to take this into account.
        remediation_count >= max_open_merge_request_limit
      end

      def remediation_profile
        Eligibility.remediation_profile(project)
      end
      strong_memoize_attr :remediation_profile

      def auto_remediation_configuration
        Eligibility.remediation_configuration(project, profile: remediation_profile).fetch(:auto_remediation, {})
      end
      strong_memoize_attr :auto_remediation_configuration

      def max_open_merge_request_limit
        auto_remediation_configuration[:open_merge_requests_limit]
      end
      strong_memoize_attr :max_open_merge_request_limit

      def severity_levels
        threshold_index = SORTED_SEVERITY_LEVELS.index(severity_threshold)

        return SORTED_SEVERITY_LEVELS unless threshold_index

        SORTED_SEVERITY_LEVELS.first(threshold_index + 1)
      end
      strong_memoize_attr :severity_levels

      def severity_threshold
        auto_remediation_configuration[:severity_level].to_sym
      end

      # Schedules one update workload if there's at least one remediable vulnerability on
      # the occurrence. Each occurrence gets its own pipeline and MR so a vulnerability is
      # individually linked, tracked, and resolved.
      def schedule_remediation(sbom_occurrence)
        vulnerability = sbom_occurrence.vulnerabilities
          .sort_by { |v| [-Vulnerability.severities[v.severity], v.id] }
          .find { |v| Eligibility.remediable?(v) }

        return unless vulnerability

        request = Request.new(sbom_occurrence:, vulnerability:)

        # A branch with an open MR is refreshed up front by refresh_open_remediations!,
        # not re-created here.
        return if open_remediations.key?(request.source_ref)

        # On a reschedule run (after a dismissed update freed a slot), don't re-pick a
        # branch a user already closed - hand the slot to the next fresh candidate.
        # Initial runs still re-evaluate it so a newer version can resurface.
        return if skip_dismissed_branches && previously_dismissed?(sbom_occurrence, request)

        response = UpdateService.new(project:).execute(request)
        self.repository_config_invalid = true if invalid_repository_config?(response)
        self.merge_requests_denied = true if denial_response?(response)

        return unless response.success?

        self.remediation_count += 1

        track_internal_event(
          "trigger_dependency_management_auto_remediation_request",
          project: project,
          additional_properties: {
            purl_type: sbom_occurrence.component.purl_type
          }
        )
      end

      # Refreshes each currently open remediation MR directly via its linked vulnerability,
      # rather than waiting to encounter it again during the occurrence scan below. A branch's
      # vulnerability can be dismissed, resolved, or fall outside the current severity/package
      # manager configuration without ever reappearing in that scan, which would otherwise
      # leave the scan unable to stop early even after the open MR limit is reached.
      def refresh_open_remediations!
        open_remediations.each_value do |merge_request|
          request = refresh_request_for(merge_request)
          next unless request

          next unless refresh_open_remediation?(merge_request)

          response = UpdateService.new(project:).execute(request)
          next if response.success?

          # UpdateService has already logged the reason once for the project.
          if invalid_repository_config?(response)
            self.repository_config_invalid = true
            break
          end

          if denial_response?(response)
            self.merge_requests_denied = true
            break
          end

          Gitlab::AppLogger.error(
            build_structured_payload_labkit(
              message: 'DependencyManagement: failed to refresh an auto-remediation merge request',
              project_id: project.id,
              merge_request_iid: merge_request.iid,
              source_branch: merge_request.source_branch,
              reason: response.message
            )
          )
        end
      end

      def invalid_repository_config?(response)
        response.error? && response.reason == :invalid_repository_config
      end

      def denial_response?(response)
        response.error? && MERGE_REQUEST_DENIAL_REASONS.include?(response.reason)
      end

      # @return [DependencyManagement::SecurityUpdate::Request, nil] a request built from the
      # merge request's linked vulnerability and its current sbom occurrence in this project,
      # or nil when the vulnerability is no longer active or no longer has a fix available.
      def refresh_request_for(merge_request)
        # max_by rather than last: the links are preloaded, so relation ordering no longer
        # applies and the most recent link has to be picked explicitly.
        vulnerability = merge_request.vulnerability_merge_request_links.max_by(&:id)&.vulnerability
        return unless vulnerability
        return unless vulnerability.detected? || vulnerability.confirmed?
        return unless Eligibility.remediable?(vulnerability)

        sbom_occurrence = vulnerability.sbom_occurrences.first
        return unless sbom_occurrence

        Request.new(sbom_occurrence:, vulnerability:)
      end

      # An open MR is normally left alone: refreshing it on every pipeline would run a
      # workload each time. Two cases still warrant a re-run.
      #
      # @return [Boolean] true when the open remediation MR should be refreshed rather than
      # skipped.
      def refresh_open_remediation?(merge_request)
        # Re-resolve once the cooldown has elapsed, so a newer patched version
        # (e.g. 5.6.0 -> 5.6.2) reaches the open MR without a workload per pipeline.
        # Checked first: the conflict state cannot change the answer when a refresh is
        # already due, and reading it is the more expensive of the two.
        if RefreshCooldown.elapsed?(merge_request)
          RefreshCooldown.hold_head(merge_request)

          return true
        end

        # A conflicted MR stays conflicted until its branch is rebuilt on the target, and a
        # workload that doesn't commit leaves the branch as it is, so the conflict path is
        # limited per branch head.
        return false unless conflicted_remediation?(merge_request)

        return false unless RefreshCooldown.conflict_refresh_due?(merge_request)

        # Counts as this window's refresh, so the cooldown cannot expire under the workload.
        RefreshCooldown.start(merge_request)

        log_conflicted_refresh(merge_request)

        true
      end

      # @return [Boolean] true when the merge request is confirmed conflicted with its
      # target branch.
      #
      # Deliberately narrow: both branches must still exist. A missing branch is a
      # different failure mode (e.g. deleted out-of-band) that this refresh path isn't
      # meant to paper over.
      #
      # Reads the recorded state rather than recomputing it: recomputing takes a
      # per-merge-request lease and hits Gitaly, and a stale answer only delays a refresh.
      def conflicted_remediation?(merge_request)
        return false unless merge_request.source_branch_exists? && merge_request.target_branch_exists?

        # GitLab records "nothing to merge" as the same unmergeable state as a real conflict,
        # so a branch still sitting at its target would be refreshed on every scheduler run.
        return false if merge_request.source_branch_sha == merge_request.target_branch_sha

        conflict_check = ::MergeRequests::Mergeability::CheckConflictStatusService
          .new(merge_request: merge_request, params: {})
          .execute

        if conflict_check.checking?
          merge_request.check_mergeability(async: true)

          return false
        end

        conflict_check.failed?
      rescue StandardError => e
        Gitlab::ErrorTracking.track_exception(e, project_id: project.id, source_branch: merge_request.source_branch)
        false
      end

      def log_conflicted_refresh(merge_request)
        Gitlab::AppLogger.info(
          build_structured_payload_labkit(
            message: 'DependencyManagement: refreshing a conflicted auto-remediation merge request',
            project_id: project.id,
            merge_request_iid: merge_request.iid,
            source_branch: merge_request.source_branch
          )
        )
      end

      # Falls back to the branch check for dismissals that predate the table.
      def previously_dismissed?(sbom_occurrence, request)
        if Feature.enabled?(:dependency_management_persisted_remediations, project)
          record = ::DependencyManagement::Remediation.for_occurrence(project, sbom_occurrence)

          return true if record&.dismissed?
        end

        user_closed_remediations_finder.dismissed_branch?(request.source_ref)
      end
    end
  end
end
