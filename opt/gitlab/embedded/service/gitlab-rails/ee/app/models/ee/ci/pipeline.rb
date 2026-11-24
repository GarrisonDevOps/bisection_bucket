# frozen_string_literal: true

module EE
  module Ci
    module Pipeline
      extend ActiveSupport::Concern
      extend ::Gitlab::Utils::Override

      prepended do
        include UsageStatistics

        # Subscriptions to this pipeline
        has_many :downstream_bridges, class_name: '::Ci::Bridge', foreign_key: :upstream_pipeline_id
        has_many :security_scans, class_name: 'Security::Scan', inverse_of: :pipeline
        has_many :security_findings, class_name: 'Security::Finding', through: :security_scans, source: :findings
        has_many :sbom_occurrence_refs, class_name: 'Sbom::OccurrenceRef', foreign_key: :pipeline_id, inverse_of: :pipeline

        has_one :dast_profiles_pipeline, class_name: 'Dast::ProfilesPipeline', foreign_key: :ci_pipeline_id
        has_one :dast_profile, class_name: 'Dast::Profile', through: :dast_profiles_pipeline, disable_joins: true

        has_one :source_project, class_name: 'Ci::Sources::Project', foreign_key: :pipeline_id

        # pipeline_id in duo_workflows_workflow_pipelines references p_ci_pipelines (gitlab_ci database),
        # so the association cannot be joined across databases; integrity is maintained via a loose foreign key.
        has_many :duo_workflow_links,
          class_name: '::Ai::DuoWorkflows::WorkflowPipeline',
          foreign_key: :pipeline_id,
          inverse_of: :pipeline
        has_many :linked_duo_workflows,
          through: :duo_workflow_links,
          source: :workflow,
          disable_joins: true

        # Legacy way to fetch security reports based on job name. This has been replaced by the reports feature.
        scope :with_legacy_security_reports, -> do
          joins(:downloadable_artifacts).where(ci_builds: { name: %w[sast secret_detection dependency_scanning container_scanning dast] })
        end
        scope :latest_completed_or_manual_pipeline_ids_per_source, ->(sha) do
          complete_or_manual
            .group(:source)
            .select('max(id) as id')
            .for_sha(sha)
        end
        scope :without_other_merge_requests, ->(merge_request_id) do
          where(merge_request_id: [nil, merge_request_id])
        end

        SBOM_REPORT_INGESTION_ERRORS_TTL = 15.days.to_i.freeze
        LATEST_PIPELINES_LIMIT = 1000

        # This structure describes feature levels
        # to access the file types for given reports
        REPORT_LICENSED_FEATURES = {
          codequality: nil,
          sast: %i[sast],
          secret_detection: %i[secret_detection],
          dependency_scanning: %i[dependency_scanning],
          container_scanning: %i[container_scanning],
          cluster_image_scanning: %i[cluster_image_scanning],
          dast: %i[dast],
          performance: %i[merge_request_performance_metrics],
          browser_performance: %i[merge_request_performance_metrics],
          load_performance: %i[merge_request_performance_metrics],
          license_scanning: %i[license_scanning],
          metrics: %i[metrics_reports],
          requirements: %i[requirements],
          requirements_v2: %i[requirements],
          coverage_fuzzing: %i[coverage_fuzzing],
          api_fuzzing: %i[api_fuzzing],
          cyclonedx: %i[dependency_scanning container_scanning],
          sarif: %i[sarif]
        }.freeze

        PIPELINE_EXECUTION_POLICIES_BUILD_SOURCES = %w[pipeline_execution_policy scan_execution_policy].freeze
        SECURITY_POLICIES_PIPELINE_SOURCES = %w[security_orchestration_policy security_policies_default_source pipeline_execution_policy_forced pipeline_execution_policy_schedule].freeze

        def self.latest_limited_pipeline_ids_per_source(pipelines, sha)
          pipelines_for_sha = pipelines.complete_or_manual.for_sha(sha).order(id: :desc).limit(LATEST_PIPELINES_LIMIT)

          from("(#{pipelines_for_sha.to_sql}) AS recent_pipelines")
            .select('DISTINCT ON (source) id')
            .order('source, id DESC')
        end

        # Newest pipeline ids of `source` at `sha`, scoped to the recent CI partitions.
        def self.recent_ids_for_sha_and_source(project, sha, source, limit:)
          project.all_pipelines.in_partition(::Ci::Partition.recent_ids).for_sha(sha)
            .with_pipeline_source(source).order(id: :desc).limit(limit).pluck(:id)
        end

        # How many of a project's newest pipelines recent_source_ids_in_window looks through.
        # There is no (project_id, source, id) index, so filtering on source first reads every
        # pipeline of that source and sorts them; walking the newest pipelines by id and
        # filtering those keeps the read bounded. A partial index would lift the cap.
        RECENT_SOURCE_IDS_WINDOW = 5_000

        # Newest pipeline ids of `source` among the project's newest `window` pipelines in the
        # recent CI partitions.
        def self.recent_source_ids_in_window(project, source, limit:, window: RECENT_SOURCE_IDS_WINDOW)
          recent_pipelines = project.all_pipelines.in_partition(::Ci::Partition.recent_ids)
            .select(:id, :source).order(id: :desc).limit(window)

          from(recent_pipelines, :p_ci_pipelines)
            .with_pipeline_source(source).order(id: :desc).limit(limit).pluck(:id)
        end

        state_machine :status do
          after_transition any => ::Ci::Pipeline.completed_with_manual_statuses do |pipeline|
            pipeline.run_after_commit do
              ::Ci::SyncReportsToReportApprovalRulesWorker.perform_async(pipeline.id)
            end
          end

          after_transition any => ::Ci::Pipeline.completed_with_manual_statuses do |pipeline|
            pipeline.run_after_commit do
              ::Security::UnenforceablePolicyRulesPipelineNotificationWorker.perform_async(pipeline.id)
            end
          end

          after_transition any => ::Ci::Pipeline.bridgeable_statuses.map(&:to_sym) do |pipeline|
            next unless pipeline.downstream_bridges.any?

            pipeline.run_after_commit do
              ::Ci::PipelineBridgeStatusWorker.perform_async(pipeline.id)
            end
          end

          after_transition any => ::Ci::Pipeline.completed_statuses do |pipeline|
            pipeline.run_after_commit do
              next unless pipeline.triggers_subscriptions?

              ::Ci::TriggerDownstreamSubscriptionsWorker.perform_async(pipeline.id)
            end
          end

          after_transition any => [:success, :failed, :canceled] do |pipeline|
            pipeline.run_after_commit do
              # Coupled to Security::AgenticAnalyzer: its workload pipelines run on a synthetic
              # ref, so default_branch? is false even when they scanned the default branch HEAD.
              # default_branch_scan? also requires a trusted flow run (see AgenticAnalyzer.trusted_ingestion_pipeline?).
              next unless pipeline.default_branch? || ::Security::AgenticAnalyzer.default_branch_scan?(pipeline)

              if project.licensed_feature_available?(:security_dashboard) && !pipeline.can_store_security_reports?
                Security::PipelineAnalyzersStatusUpdateWorker.perform_async(pipeline.id)
              end

              if project.licensed_feature_available?(:security_scan_profiles)
                Security::ScanProfileStatus::UpdateWorker.perform_async(pipeline.id)
              end
            end
          end

          after_transition any => :skipped do |pipeline|
            pipeline.run_after_commit do
              Security::Policies::SkipPipelinesAuditWorker.perform_async(pipeline.id)
            end
          end

          after_transition any => :failed do |pipeline|
            pipeline.run_after_commit do
              if should_audit_security_policy_pipeline_failure?(pipeline)
                Security::Policies::FailedPipelinesAuditWorker.perform_async(pipeline.id)
              end
            end
          end
        end
      end

      def needs_touch?
        updated_at < 5.minutes.ago
      end

      def triggers_subscriptions?
        # Currently we trigger subscriptions only for tags.
        tag? && project_has_subscriptions?
      end

      def security_reports(report_types: [])
        reports_scope = report_types.empty? ? ::Ci::JobArtifact.security_reports : ::Ci::JobArtifact.security_reports(file_types: report_types)
        types_to_collect = report_types.empty? ? ::Enums::Ci::JobArtifact.security_report_file_types : report_types

        ::Gitlab::Ci::Reports::Security::Reports.new(self).tap do |security_reports|
          latest_report_builds_in_self_and_project_descendants(reports_scope).includes(pipeline: { project: :route }).find_each do |build|
            build.collect_security_reports!(security_reports, report_types: types_to_collect)
          end
        end
      end

      def batch_lookup_report_artifact_for_file_types(file_types)
        file_types_to_search = []
        file_types.each do |file_type|
          file_types_to_search.append(file_type) if available_licensed_report_type?(file_type)
        end

        return unless file_types_to_search.present?

        super(file_types_to_search)
      end

      def metrics_report
        ::Gitlab::Ci::Reports::Metrics::Report.new.tap do |metrics_report|
          latest_report_builds_in_self_and_project_descendants(::Ci::JobArtifact.of_report_type(:metrics)).each do |build|
            build.collect_metrics_reports!(metrics_report)
          end
        end
      end

      # Metrics report limited to the artifacts `user` may read. `user` may be
      # nil for an anonymous request (public artifacts only).
      def accessible_metrics_reports(user)
        ::Gitlab::Ci::Reports::Metrics::Report.new.tap do |metrics_report|
          # Authz::JobArtifactAccess.for reads each build's pipeline
          latest_report_builds_in_self_and_project_descendants(::Ci::JobArtifact.of_report_type(:metrics))
            .preload(:pipeline).each do |build| # rubocop:disable Rails/FindEach -- same iteration as metrics_reports; find_each would batch and reorder
            next unless build.report_readable_by?(:metrics, user)

            build.collect_metrics_reports!(metrics_report)
          end
        end
      end

      def sbom_reports(self_and_project_descendants: false)
        report_builds = if self_and_project_descendants
                          method(:latest_report_builds_in_self_and_project_descendants)
                        else
                          method(:latest_report_builds)
                        end

        ::Gitlab::Ci::Reports::Sbom::Reports.new.tap do |sbom_reports|
          report_builds.call(::Ci::JobArtifact.of_report_type(:sbom)).each do |build|
            build.collect_sbom_reports!(sbom_reports)
          end
        end
      end

      # Sorted ids of the latest SBOM builds in the hierarchy. Uses an EXISTS filter rather
      # than the eager-loading `latest_report_builds_*` join, so each build appears once.
      def sbom_report_build_ids_in_self_and_project_descendants
        builds_in_self_and_project_descendants
          .with_existing_job_artifacts(::Ci::JobArtifact.of_report_type(:sbom))
          .ids.sort
      end

      # Sbom reports limited to the artifacts `user` may read. `user` may be nil for
      # an anonymous request (public artifacts only). Used by the license scanning
      # comparison path; system/internal callers use the unscoped `sbom_reports`.
      def accessible_sbom_reports(user, self_and_project_descendants: false)
        report_builds = if self_and_project_descendants
                          method(:latest_report_builds_in_self_and_project_descendants)
                        else
                          method(:latest_report_builds)
                        end

        ::Gitlab::Ci::Reports::Sbom::Reports.new.tap do |sbom_reports|
          # Authz::JobArtifactAccess.for reads each build's pipeline
          report_builds.call(::Ci::JobArtifact.of_report_type(:sbom)).preload(:pipeline).each do |build| # rubocop:disable Rails/FindEach -- same iteration as sbom_reports; find_each would batch and reorder
            next unless build.report_readable_by?(:sbom, user)

            build.collect_sbom_reports!(sbom_reports)
          end
        end
      end

      ##
      # Check if it's a merge request pipeline with the HEAD of source and target branches
      # TODO: Make `Ci::Pipeline#latest?` compatible with merge request pipelines and remove this method.
      def latest_merged_result_pipeline?
        merged_result_pipeline? &&
          source_sha == merge_request.diff_head_sha &&
          target_sha == merge_request.target_branch_sha
      end

      override :merge_request_event_type
      def merge_request_event_type
        return unless merge_request?

        strong_memoize(:merge_request_event_type) do
          merge_train_pipeline? ? :merge_train : super
        end
      end

      override :retryable?
      def retryable?
        # When a merge train pipeline is complete, retrying its jobs won't add the MR
        # back to the train, so retrying it is pointless for the user.
        return false if completed_merge_train_pipeline?

        super
      end

      override :merge_train_pipeline?
      def merge_train_pipeline?
        merged_result_pipeline? && merge_train_ref?
      end

      # Column-only variant of `merge_train_pipeline? && complete?`. Unlike
      # `merge_train_pipeline?` (via `merge_request?`), it never loads the
      # merge_request association, so it is safe to call per record in batched
      # paths such as GraphQL pipeline lists and pipeline-wide job retries.
      # Folding this back into `merge_train_pipeline?` is tracked in
      # https://gitlab.com/gitlab-org/gitlab/-/issues/607453.
      def completed_merge_train_pipeline?
        complete? && merge_request_id.present? && target_sha.present? && merge_train_ref?
      end

      def latest_failed_security_builds
        security_builds.select(&:latest?)
                       .select(&:failed?)
      end

      def license_scan_completed?
        latest_report_builds(::Ci::JobArtifact.of_report_type(:license_scanning)).exists?
      end

      def can_ingest_sbom_reports?
        project.namespace.ingest_sbom_reports_available? && has_sbom_reports?
      end

      def has_sbom_reports?
        complete_or_manual_and_has_reports?(::Ci::JobArtifact.of_report_type(:sbom))
      end

      def has_dependency_scanning_reports?
        complete_or_manual_and_has_reports?(::Ci::JobArtifact.of_report_type(:dependency_list))
      end

      def can_store_security_reports?
        project.can_store_security_reports? && has_security_reports?
      end

      # MR pipelines run on `refs/merge-requests/:iid/(head|merge)`, which users cannot track, so
      # their results belong to the source branch. Excluded: fork MRs, whose source branch is in
      # another repository, and default-branch MRs, whose context only pipelines on it may write to.
      def tracked_context_ref
        return ref unless merge_request? && merge_request.source_project_id == project_id
        return ref if merge_request.source_branch == project.default_branch_or_main

        merge_request.source_branch
      end

      # We want all the `security_findings` records for a particular pipeline to be stored in
      # the same partition, therefore, we check if the pipeline already has a `security_scan`.
      #
      # - If it has, then we use the partition number of the existing security_scan to make sure
      # that the new `security_findings` will be stored in the same partition with the existing ones.
      # - If it does not have a security_scan yet, then we can basically use the latest partition
      # of the `security_findings` table.
      def security_findings_partition_number
        @security_findings_partition_number ||= security_scans.first&.findings_partition_number || Security::Finding.active_partition_number
      end

      def has_security_findings_in_self_and_descendants?
        Security::Finding.by_project_id_and_pipeline_ids(project_id, self_and_project_descendants.pluck(:id)).exists?
      end

      def has_security_report_ingestion_warnings?
        security_scans.with_warnings.exists?
      end

      def has_security_report_ingestion_errors?
        security_scans.with_errors.exists?
      end

      def has_sbom_report_ingestion_errors?
        sbom_report_ingestion_errors.present?
      end

      # @param sbom_errors [Array<Hash{message: String, help_link: String}, Array<String>>]
      def set_sbom_report_ingestion_errors(sbom_errors)
        return if sbom_errors.blank?

        existing_errors = sbom_report_ingestion_errors || []

        new_errors = sbom_errors.map { |e| [normalize_sbom_error(e)] }

        # Ensure error messages are kept under a manageable size
        combined_errors = (existing_errors + new_errors).first(10)

        value = combined_errors.to_json
        ::Gitlab::Redis::SharedState.with do |redis|
          redis.set(
            sbom_report_ingestion_errors_redis_key,
            value,
            ex: SBOM_REPORT_INGESTION_ERRORS_TTL
          )
        end
      end

      def sbom_report_ingestion_errors
        ::Gitlab::Redis::SharedState.with { |redis| redis.get(sbom_report_ingestion_errors_redis_key) }
                                    .then { |sbom_errors| ::Gitlab::Json.safe_parse(sbom_errors) if sbom_errors }
      end

      def total_ci_minutes_consumed
        ::Gitlab::Ci::Minutes::PipelineConsumption.new(self).amount
      end

      def security_scan_types
        security_scans.pluck(:scan_type)
      end

      def self_and_descendant_security_scans
        Security::Scan.where(pipeline_id: self_and_project_descendants.pluck(:id))
      end

      # As the `created_at` attribute of the security scans is used in the partition dropping logic,
      # we are using the same value for all the security scans of the same pipeline to avoid extending
      # the lifetime of partitions when the pipeline is retried.
      def security_scans_created_at
        @security_scans_created_at ||= security_scans.pick(:created_at) || Time.zone.now
      end

      def has_security_reports?
        security_and_license_scanning_file_types = ::Enums::Ci::JobArtifact.all_security_report_file_types

        complete_or_manual_and_has_reports?(::Ci::JobArtifact.with_file_types(security_and_license_scanning_file_types))
      end

      def all_security_jobs_complete?
        builds = builds_in_self_and_project_descendants.without_status(:manual)

        # `security_job?` reads each build's job definition, so narrow to unfinished builds and preload it.
        builds.incomplete.preload(:job_definition).none?(&:security_job?)
      end

      def security_reports_ready_for_ingestion?(scan_types = nil)
        return false if builds_in_self_and_project_descendants
                          .latest
                          .with_status(::Ci::HasStatus::ACTIVE_STATUSES)
                          .any?(&:security_job?)

        build_ids =
          builds_in_self_and_project_descendants
            .latest
            .complete
            .joins(:job_artifacts)
            .merge(::Ci::JobArtifact.security_reports)
            .distinct
            .pluck_primary_key

        return true if build_ids.empty?

        scan_types ||= Security::Scan.scan_types.keys

        !Security::Scan.processing?(self, scan_types, build_ids)
      end

      def has_all_security_policies_reports?
        can_store_security_reports? && can_ingest_sbom_reports?
      end

      # All opened merge requests for which the current pipeline that runs/ran for the head commit
      def opened_merge_requests_with_head_sha
        shas = [sha, source_sha].compact.uniq
        mr_table = ::MergeRequest.arel_table
        diff_table = ::MergeRequestDiff.arel_table

        merge_requests =
          if merge_request? || ::Feature.disabled?(:policy_head_sha_lookup_without_diff_commits, project)
            all_merge_requests
          else
            # The head_commit_sha check below makes the diff commits join in all_merge_requests
            # redundant, and that join misses merge requests whose latest diff has no commits.
            ::MergeRequest.where(source_project_id: project_id, source_branch: ref)
          end

        merge_requests
          .opened
          .where(
            "EXISTS (?)",
            ::MergeRequestDiff.select(1)
              .where(mr_table[:latest_merge_request_diff_id].eq(diff_table[:id]))
              .where(head_commit_sha: shas)
          )
          # Every caller iterates these and reads the target project, which for a
          # fork merge request is not the pipeline's own project.
          .preload(:target_project)
      end

      def merge_requests_as_base_pipeline
        merge_request_diffs = ::MergeRequestDiff.where(project_id: project_id, base_commit_sha: sha).regular
        project.merge_requests.opened.by_latest_merge_request_diffs(merge_request_diffs)
      end

      private

      # Normalizes an error into a consistent hash format.
      # Supports:
      #   - Hash: { message:, help_link: }
      #   - Array: ["error message"]
      #   - String: stored without a help link
      def normalize_sbom_error(error)
        result = case error
                 when Hash
                   { "message" => error[:message].to_s, "help_link" => error[:help_link] }
                 when Array
                   # Format passed by IngestReportsService: report.errors returns an array of strings
                   { "message" => error.first.to_s, "help_link" => nil }
                 else
                   { "message" => error.to_s, "help_link" => nil }
                 end

        result.merge("message" => result["message"].truncate(1024))
      end

      def project_has_subscriptions?
        project.feature_available?(:ci_project_subscriptions) &&
          project.downstream_project_subscriptions.any?
      end

      def merge_train_ref?
        ::MergeRequest.merge_train_ref?(ref)
      end

      def available_licensed_report_type?(file_type)
        feature_names = REPORT_LICENSED_FEATURES.fetch(file_type)
        feature_names.nil? || feature_names.any? { |feature| project.feature_available?(feature) }
      end

      def security_builds
        @security_builds ||= ::Security::SecurityJobsFinder.new(pipeline: self).execute
      end

      def sbom_report_ingestion_errors_redis_key
        "sbom_report_ingestion_errors/#{id}"
      end

      def should_audit_security_policy_pipeline_failure?(pipeline)
        pipeline_created_by_security_policies?(pipeline.source) || pipeline_with_security_policy_jobs? || pipeline_with_security_policy_errors?(pipeline)
      end

      def pipeline_created_by_security_policies?(source)
        SECURITY_POLICIES_PIPELINE_SOURCES.include?(source)
      end

      def pipeline_with_security_policy_jobs?
        builds.joins(:job_source).where(p_ci_build_sources: { source: PIPELINE_EXECUTION_POLICIES_BUILD_SOURCES }).exists?
      end

      def pipeline_with_security_policy_errors?(pipeline)
        pipeline.messages.pipeline_execution_policy_failure.exists?
      end
    end
  end
end
