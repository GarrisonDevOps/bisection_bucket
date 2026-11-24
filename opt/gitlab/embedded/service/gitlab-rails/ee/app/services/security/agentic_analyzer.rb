# frozen_string_literal: true

module Security
  # Recognizes duo_workflow workload pipelines that scanned the default branch (its HEAD now,
  # or its HEAD when the scan was dispatched), letting their security findings ingest into the
  # Vulnerability Report when the run is trusted (see trusted_ingestion_pipeline?).
  module AgenticAnalyzer
    module_function

    # Set on the workload job at dispatch: by Ai::DuoWorkflows::StartWorkflowService (the branch
    # the workload ref was cut from) and by Ai::FlowTriggers::RunService (the triggering branch).
    SOURCE_BRANCH_VARIABLE = 'DUO_WORKFLOW_SOURCE_BRANCH'

    # Report types agentic analyzers publish (see
    # Ai::Catalog::FoundationalFlow#report_artifacts, e.g. { sast: [...] }).
    # Every lookup only considers them on trusted workloads (see trusted_analyzers_by_pipeline_id).
    AGENTIC_REPORT_TYPES = %w[sast].freeze

    # Flow trigger events that carry no input from the person whose action fired them: GitLab
    # dispatches commit_to_default_branch, and people who manage flow triggers (Maintainer or
    # above) configure schedules.
    TRUSTED_TRIGGER_EVENT_TYPES = %w[commit_to_default_branch scheduled].freeze

    # We only need the newest workload pipeline(s) at this SHA, so cap the id materialization.
    # The branch scan lookup also uses it to cap the full scans it keeps. Partial scans are
    # filtered out before this cap, so they cannot crowd out the full scans among the
    # MAX_BRANCH_SCAN_WORKLOADS pipelines looked through.
    MAX_WORKLOAD_CANDIDATES = 50

    # Upper bound on the open merge requests re-evaluated after an agentic analyzer scan (newest first).
    MAX_MERGE_REQUESTS_TO_SYNC = 20

    # Upper bound on the scans (and Gitaly ancestry checks) tried when looking for the
    # latest agentic analyzer scan of a branch.
    MAX_BRANCH_SCAN_CANDIDATES = 5

    # Upper bound on the newest duo_workflow pipelines looked through for those scans,
    # partial (MR) scans or not: frequent partial scans do use up this cap.
    MAX_BRANCH_SCAN_WORKLOADS = 500

    def default_branch_scan?(pipeline)
      project = pipeline.project
      return false unless pipeline.workload? && pipeline.source.to_sym == :duo_workflow && enabled?(project)

      Gitlab::SafeRequestStore.fetch([:agentic_analyzer_default_branch_scan, pipeline.id]) do
        unless trusted_ingestion_pipeline?(pipeline)
          log_default_branch_scan(pipeline, false, 'untrusted_flow_trigger')
          next false
        end

        default_sha = project.commit(project.default_branch)&.id

        if default_sha.blank?
          log_default_branch_scan(pipeline, false, 'default_branch_not_found')
          false
        elsif pipeline.sha == default_sha
          true
        else
          source_branch = dispatch_source_branch(pipeline)

          if source_branch.present? && source_branch == project.default_branch
            # pipeline.sha is the default-branch HEAD at dispatch, so a push during a long scan
            # keeps its results, but a SHA a force push rewrote off the default branch does not.
            dispatch_sha_on_default_branch?(pipeline, default_sha)
          else
            reason = source_branch.present? ? 'not_dispatched_for_default_branch' : 'dispatch_branch_unknown'
            log_default_branch_scan(pipeline, false, reason)
            false
          end
        end
      end
    end

    def dispatch_sha_on_default_branch?(pipeline, default_sha)
      on_default_branch = pipeline.project.repository.ancestor?(pipeline.sha, default_sha)
      reason = on_default_branch ? 'default_branch_moved_since_dispatch' : 'dispatch_sha_not_on_default_branch'
      log_default_branch_scan(pipeline, on_default_branch, reason)
      on_default_branch
    end

    # Derived from the workload job's own dispatch-time variables, so no new column is needed.
    # Nil for workloads started before the variable existed.
    def dispatch_source_branch(pipeline)
      Gitlab::SafeRequestStore.fetch([:agentic_analyzer_dispatch_source_branch, pipeline.id]) do
        source_branch_of(pipeline.builds.order_id_asc.first)
      end
    end

    def source_branch_of(build)
      build&.yaml_variables&.find { |variable| variable[:key].to_s == SOURCE_BRANCH_VARIABLE }&.dig(:value)
    end

    # Fills dispatch_source_branch's request cache for `pipelines` with one first-job query.
    def preload_dispatch_source_branches(pipelines)
      return if pipelines.empty? || !Gitlab::SafeRequestStore.active?

      # rubocop:disable CodeReuse/ActiveRecord -- bounded first-job lookup in security service
      first_builds = ::Ci::Build.in_partition(pipelines.map(&:partition_id).uniq)
        .where(commit_id: pipelines.map(&:id)).select('DISTINCT ON (commit_id) *')
        .order(:commit_id, :id).preload(:job_definition).index_by(&:commit_id)
      # rubocop:enable CodeReuse/ActiveRecord
      pipelines.each do |pipeline|
        Gitlab::SafeRequestStore.fetch([:agentic_analyzer_dispatch_source_branch, pipeline.id]) do
          source_branch_of(first_builds[pipeline.id])
        end
      end
    end

    def log_default_branch_scan(pipeline, default_branch_scan, reason)
      Gitlab::AppJsonLogger.info(
        Labkit::Fields::CLASS_NAME => name,
        message: 'Agentic analyzer default-branch scan check',
        default_branch_scan: default_branch_scan,
        default_branch_scan_reason: reason,
        Labkit::Fields::GL_PROJECT_ID => pipeline.project_id,
        Labkit::Fields::GL_PIPELINE_ID => pipeline.id
      )
    end

    def scan_marker_key(project_id, sha)
      "#{name}::sast_scan::#{project_id}::#{sha}"
    end

    # Marks project+commit as having an agentic SAST scan, so MR pages for unmarked commits skip the
    # CI lookup. Lives as long as the scan itself (Security::Scan.stale_after). Recorded with the flag
    # off too, so turning it on does not hide scans that were already stored.
    def record_scan(pipeline)
      return unless pipeline.workload? && pipeline.source.to_sym == :duo_workflow

      Gitlab::Redis::SharedState.with do |redis|
        redis.set(scan_marker_key(pipeline.project_id, pipeline.sha), 1, ex: ::Security::Scan.stale_after.to_i)
      end
    end

    # A present marker only means "maybe" (the SQL still decides); an absent one skips the SQL.
    def scan_recorded?(project, sha)
      return false if sha.blank?

      Gitlab::SafeRequestStore.fetch([:agentic_analyzer_scan_recorded, project.id, sha]) do
        Gitlab::Redis::SharedState.with do |redis|
          redis.exists?(scan_marker_key(project.id, sha)) # rubocop:disable CodeReuse/ActiveRecord -- Redis, not AR
        end
      end
    end

    # Callers check this first. Elsewhere it costs at most one memoized top-level group query; where
    # the per-instance gate applies, also a cached per-instance enablement lookup.
    # Flags are checked on the top-level group, so one flag actor covers all of a customer's projects.
    def enabled?(project)
      flow = ::Ai::Catalog::FoundationalFlow.bl_security_experimental
      # Where GitLab enables the flow per instance, ingestion needs that too; on Dedicated it replaces the flag.
      if flow.per_instance_gate_applies?
        return false unless flow.enabled_for?(project.root_ancestor)
        return true if flow.enablement_replaces_feature_flags?
      end

      Feature.enabled?(:agentic_analyzer_security_ingestion, project.root_ancestor)
    end

    # Whether `pipeline` or one of its child pipelines ran a successful (latest) scan of
    # `report_type`, whether or not it produced findings.
    def pipeline_has_successful_scan?(pipeline, report_type)
      ::Security::Scan.by_pipeline_ids(pipeline.self_and_project_descendants.pluck_primary_key)
        .by_scan_types(report_type).latest_successful.exists?
    end

    # The latest agentic workload pipeline that scanned `sha` with a successful scan of
    # `report_types`, used to resolve an MR security head pipeline (the base comes from
    # latest_branch_scan_pipelines_for). Resolves the pipeline via the scan's
    # partition-aware loader (no cross-schema re-query).
    def scan_pipeline_for(project, sha, report_types = AGENTIC_REPORT_TYPES)
      latest_agentic_scan(project, sha, report_types)&.pipeline
    end

    # Agentic-analyzer workload pipeline ids at `sha` (succeeded scans): per analyzer, at most the
    # latest full and the latest partial run, so re-runs at one commit are not counted twice, an
    # older run's findings do not linger, and one analyzer's run does not hide another's.
    def scan_pipeline_ids_for(project, sha)
      return [] unless sha && enabled?(project)

      analyzers = workload_analyzers_at(project, sha)
      scans = agentic_scans_in(project, analyzers.keys)
      [scans.without_partial_scan, scans.partial].flat_map do |relation|
        # rubocop:disable CodeReuse/ActiveRecord -- bounded per-sha read in security service
        ids = relation.distinct.limit(MAX_WORKLOAD_CANDIDATES).pluck(:pipeline_id)
        # rubocop:enable CodeReuse/ActiveRecord
        next [] if ids.empty?

        ids.group_by { |id| analyzers[id] }.values.map(&:max)
      end.uniq
    end

    # Whether `pipeline` is a recognized workload pipeline with a succeeded agentic analyzer
    # scan, i.e. one RelatedPipelines includes in approval policy evaluation.
    def scan_pipeline?(pipeline)
      return false unless pipeline.workload? && pipeline.source.to_sym == :duo_workflow

      scan_pipeline_ids_for(pipeline.project, pipeline.sha).include?(pipeline.id)
    end

    # Open merge requests whose latest diff head is `sha`, newest first (indexed on head_commit_sha, bounded).
    def opened_merge_requests_at(project, sha)
      project.merge_requests.opened.with_latest_diff_head_sha(sha)
        .with_order_id_desc.limit(MAX_MERGE_REQUESTS_TO_SYNC)
        .preload_head_pipeline_and_latest_diff # read per MR by diff_head_pipeline
    end

    def latest_agentic_scan(project, sha, report_types = AGENTIC_REPORT_TYPES)
      # rubocop:disable CodeReuse/ActiveRecord -- scoped read in security service
      agentic_scans(project, sha, report_types).order(pipeline_id: :desc).first
      # rubocop:enable CodeReuse/ActiveRecord
    end

    def agentic_scans(project, sha, report_types = AGENTIC_REPORT_TYPES)
      return ::Security::Scan.none unless sha && enabled?(project)

      agentic_scans_in(project, workload_pipeline_ids_at(project, sha), report_types)
    end

    # Per analyzer (newest first), the latest full trusted scan of a commit on `branch`, the base of
    # an MR targeting it, limited to `analyzers`. Scans run on a schedule, so the branch
    # HEAD has usually moved on since, and an exact-SHA match would make every pre-existing finding look new.
    def latest_branch_scan_pipelines_for(project, branch, analyzers:)
      return [] unless enabled?(project)

      branch_sha = project.commit(branch)&.id
      return [] unless branch_sha

      candidate_ids = ::Ci::Pipeline.recent_source_ids_in_window(project, :duo_workflow,
        limit: MAX_BRANCH_SCAN_WORKLOADS)
      # Filter on full scans first, in one query, so only pipelines with one take the
      # flow lookup. Capped at MAX_WORKLOAD_CANDIDATES to bound that lookup's id lists.
      # Their pipelines load in bulk, for the hook-run branch check and the ancestry check.
      # rubocop:disable CodeReuse/ActiveRecord -- scoped, bounded read in security service
      scans = agentic_scans_in(project, candidate_ids).without_partial_scan
        .order(pipeline_id: :desc).limit(MAX_WORKLOAD_CANDIDATES)
        .with_partition_aware_preload.preload(pipeline: :project).to_a
      # rubocop:enable CodeReuse/ActiveRecord
      scans = scans.uniq(&:pipeline_id)
      by_pipeline = trusted_analyzers_by_pipeline_id(scans.map(&:pipeline_id)) do |ids|
        scans.select { |scan| ids.include?(scan.pipeline_id) }.map(&:pipeline)
      end
      by_pipeline = by_pipeline.select { |_, analyzer| analyzers.include?(analyzer) }

      newest_branch_scan_per_analyzer(project, branch_sha, scans, by_pipeline)
    end

    def newest_branch_scan_per_analyzer(project, branch_sha, scans, analyzers)
      scans.select { |scan| analyzers.key?(scan.pipeline_id) }.group_by { |scan| analyzers[scan.pipeline_id] }
        .values.first(MAX_BRANCH_SCAN_CANDIDATES).filter_map do |analyzer_scans|
          analyzer_scans.first(MAX_BRANCH_SCAN_CANDIDATES).map(&:pipeline).find do |pipeline|
            pipeline.sha == branch_sha || project.repository.ancestor?(pipeline.sha, branch_sha)
          end
        end
    end

    def agentic_scans_in(project, candidate_ids, report_types = AGENTIC_REPORT_TYPES)
      return ::Security::Scan.none if candidate_ids.empty?

      ::Security::Scan
        .by_project(project)
        .by_scan_types(report_types)
        .succeeded
        .latest
        .by_pipeline_ids(candidate_ids)
    end

    # Whether `pipeline`'s findings may count for the project's security state, like a
    # default-branch CI job's (see trusted_analyzers_by_pipeline_id).
    def trusted_ingestion_pipeline?(pipeline)
      trusted_analyzer_for(pipeline).present?
    end

    # The analyzer (flow reference) of a trusted workload pipeline, or nil.
    def trusted_analyzer_for(pipeline)
      Gitlab::SafeRequestStore.fetch([:agentic_analyzer_trusted_analyzer, pipeline.id]) do
        trusted_analyzers_by_pipeline_id([pipeline.id]) { [pipeline] }[pipeline.id].to_s
      end.presence
    end

    # Trusted workload pipeline id => its analyzer (the flow its workflow ran): the business logic
    # security flow, another GitLab report flow on its own triggers, a trusted trigger, or a hook
    # from a default-branch pipeline. The block loads hook runs' pipelines for that branch check.
    def trusted_analyzers_by_pipeline_id(pipeline_ids)
      workflow_ids = workflow_ids_by_pipeline_id(pipeline_ids)
      return {} if workflow_ids.empty?

      workflows = ::Ai::DuoWorkflows::Workflow.id_in(workflow_ids.values).limit(workflow_ids.size)
        .select(:id, :workflow_definition, :trigger_event_type, :ai_catalog_item_version_id).index_by(&:id)
      runs = workflow_ids.transform_values { |workflow_id| workflows[workflow_id] }.compact
      hook_ids = runs.filter_map { |id, workflow| id if !trusted_workflow?(workflow) && hook_run?(workflow) }
      hooks = hook_ids.empty? ? {} : yield(hook_ids).index_by(&:id)
      preload_dispatch_source_branches(hooks.values)

      runs.select { |id, workflow| trusted_workflow?(workflow) || default_branch_hook?(hooks[id]) }
        .transform_values(&:workflow_definition)
    end

    def trusted_workflow?(workflow)
      workflow.workflow_definition == ::Ai::Catalog::FoundationalFlow::BL_SECURITY_FLOW_REFERENCE ||
        report_flow_trigger_events[workflow.workflow_definition]&.include?(workflow.trigger_event_type) ||
        TRUSTED_TRIGGER_EVENT_TYPES.include?(workflow.trigger_event_type)
    end

    # Only runs RunService dispatched itself record the triggering branch. A catalog flow run records the
    # branch its workload was cut from, which is the default branch for a tag or deleted-branch pipeline.
    def hook_run?(workflow)
      workflow.trigger_event_type == 'pipeline_hooks' && workflow.ai_catalog_item_version_id.nil?
    end

    def default_branch_hook?(pipeline)
      return false unless pipeline

      # Both sides can be nil (non-branch trigger, no default branch); nil must not match nil.
      branch = dispatch_source_branch(pipeline)
      branch.present? && branch == pipeline.project.default_branch
    end

    # Reference => trigger event names of the GitLab foundational flows that publish reports.
    # The flow definitions are static, so this is built once.
    def report_flow_trigger_events
      @report_flow_trigger_events ||= ::Ai::Catalog::FoundationalFlow.all
        .select { |flow| flow.report_artifacts.present? }
        .to_h do |flow|
          events = Array(flow.triggers).map { |id| ::Ai::FlowTrigger::EVENT_TYPES.key(id).to_s }
          [flow.foundational_flow_reference, events]
        end.freeze
    end

    # Workload pipeline id => its workflow id. The tables span the CI and main databases, so
    # each hop is a bounded id lookup instead of a join (one row per id on each hop).
    def workflow_ids_by_pipeline_id(pipeline_ids)
      return {} if pipeline_ids.empty?

      # rubocop:disable CodeReuse/ActiveRecord -- bounded id lookups in security service
      pipeline_ids_by_workload_id = ::Ci::Workloads::Workload.in_partition(::Ci::Partition.recent_ids)
        .where(pipeline_id: pipeline_ids).limit(pipeline_ids.size).pluck(:id, :pipeline_id).to_h
      ::Ai::DuoWorkflows::WorkflowsWorkload
        .where(workload_id: pipeline_ids_by_workload_id.keys).limit(pipeline_ids.size)
        .pluck(:workload_id, :workflow_id).to_h
        .transform_keys { |workload_id| pipeline_ids_by_workload_id[workload_id] }
      # rubocop:enable CodeReuse/ActiveRecord
    end

    # Bounded lookup of duo_workflow pipeline ids (the same source default_branch_scan?
    # requires) at `sha` in the recent CI partitions, kept to trusted runs.
    def workload_pipeline_ids_at(project, sha)
      workload_analyzers_at(project, sha).keys
    end

    def workload_analyzers_at(project, sha)
      Gitlab::SafeRequestStore.fetch([:agentic_workload_analyzers, project.id, sha]) do
        ids = ::Ci::Pipeline.recent_ids_for_sha_and_source(project, sha, :duo_workflow, limit: MAX_WORKLOAD_CANDIDATES)
        trusted_analyzers_by_pipeline_id(ids) do |hook_ids|
          project.all_pipelines.in_partition(::Ci::Partition.recent_ids).id_in(hook_ids).to_a
        end
      end
    end

    # The commit an agentic analyzer scan of `pipeline`'s code would have run on. A
    # merged-results pipeline runs on a temporary merge commit, so use its source commit instead
    # (falling back to its sha), like Security::RelatedPipelinesFinder but only the source commit.
    def scanned_sha(pipeline)
      pipeline.merged_result_pipeline? ? pipeline.source_sha.presence || pipeline.sha : pipeline.sha
    end

    # scan_pipeline_ids_for at the commit `pipeline` scanned (see scanned_sha), so a
    # merged-results pipeline still finds the scan of its source commit.
    def scan_pipeline_ids_for_pipeline(pipeline)
      scan_pipeline_ids_for(pipeline.project, scanned_sha(pipeline))
    end
    private_class_method :dispatch_sha_on_default_branch?, :dispatch_source_branch, :log_default_branch_scan,
      :source_branch_of, :preload_dispatch_source_branches, :trusted_workflow?, :hook_run?, :default_branch_hook?,
      :newest_branch_scan_per_analyzer
  end
end
