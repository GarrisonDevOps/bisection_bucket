# frozen_string_literal: true

module Analytics
  module Orbit
    class ContextService
      VERSION = '1.4.0'
      MAX_RELATED_ITEMS = 10
      MAX_RELATED_CANDIDATES = 50
      MAX_USERS = 10
      MAX_LABELS = 20
      MAX_DESCRIPTION = 6000
      MAX_CHANGED_FILES = 100
      MAX_LINE_RANGES = 20
      MAX_FILE_DIFF_LINES = 40
      MAX_DIFF_LINES = 200
      MAX_FAILED_JOBS = 5
      MAX_TRACED_JOBS = 3
      MAX_PIPELINE_CANDIDATES = 20
      MAX_PIPELINE_JOBS = 50
      MAX_NOTE_CANDIDATES = 200
      MAX_NOTES = 40
      MAX_NOTE_CHARS = 1500
      NOT_FOUND = 'not_found'
      LINK_RELATION = 'CLOSES'
      # A branch resolved by name; `id` is the branch name, as there is no database row.
      BranchRef = Data.define(:project, :branch) do
        def id
          branch.name
        end
      end

      def initialize(current_user, token, expand:, format:, request_context:, env:, access_token: nil)
        @current_user = current_user
        @token = token
        @expand = expand
        @format = format
        @request_context = request_context
        @env = env
        @access_token = access_token
        @granular_scope_authorizations = {}
      end

      def execute
        { version: VERSION, entities: [entity] }
      end

      private

      attr_reader :current_user, :token, :expand, :format, :request_context, :env, :access_token

      def entity
        parsed = ContextToken.parse(token)
        return unfound(parsed.error) if parsed.error

        type, record = parsed.ref_lookup? ? find_ref(parsed) : [parsed.type, find_record(parsed)]
        return unfound(NOT_FOUND, parsed) unless record && readable?(record)

        found(type, record)
      end

      def unfound(code, parsed = nil)
        { token: token, type: nil, id: parsed&.id&.to_s, found: false, error: { code: code }, expansion: nil }
      end

      def found(type, record)
        # Build the summary first: the expansion marks the request IO-bound and releases DB connections.
        summary = summary(type, record)

        {
          token: token, resolved_token: resolved_record_token(type, record), type: type, id: record.id.to_s,
          found: true, summary: summary, expansion: expansion(type, record)
        }
      end

      def expansion(type, record)
        return unless expand

        ContextExpansionService.new(
          current_user, type: type, id: record.id, traversal_path: traversal_path(record), format: format,
          request_context: request_context, env: env
        ).execute
      end

      def resolved_token(type, id)
        "#{type}[#{id}]"
      end

      def resolved_record_token(type, record)
        return "#{record.project.full_path}@#{record.id}" if [ContextToken::BRANCH, ContextToken::COMMIT].include?(type)

        resolved_token(type, record.id)
      end

      # Authorizes the repository before any Gitaly call, so a caller without access cannot probe which refs exist.
      # A ref resolves to a branch of that name first, then to a commit when it is a SHA.
      def find_ref(parsed)
        project = Project.find_by_full_path(parsed.path)
        return unless project && Ability.allowed?(current_user, :read_code, project)

        branch = find_branch(project, parsed.ref) if parsed.type == ContextToken::BRANCH
        return [ContextToken::BRANCH, branch] if branch

        commit = find_commit(project, parsed.ref)
        [ContextToken::COMMIT, commit] if commit
      end

      def find_branch(project, name)
        return unless granular_scope_allowed?(:read_branch, project)

        branch = project.repository.find_branch(name)
        BranchRef.new(project: project, branch: branch) if branch
      rescue ::Gitlab::Git::Repository::NoRepository, ::Gitlab::Git::CommandError
        nil
      end

      def find_commit(project, sha)
        return unless ContextToken.commit_sha?(sha) && granular_scope_allowed?(:read_commit, project)

        project.commit(sha)
      rescue ::Gitlab::Git::Repository::NoRepository, ::Gitlab::Git::CommandError
        nil
      end

      def find_record(parsed)
        return find_by_id(parsed) unless parsed.iid_lookup?

        record = find_by_iid(parsed)
        parsed.epic && !record&.epic_work_item? ? nil : record
      end

      def find_by_id(parsed)
        return Epic.find_by_id(parsed.id)&.work_item if parsed.epic

        record = model_for(parsed.type).find_by_id(parsed.id)
        # A job or pipeline URL only resolves under its own project.
        parsed.path && record&.project != find_container(parsed) ? nil : record
      end

      def find_by_iid(parsed)
        container = find_container(parsed)
        iid = parsed.iid

        case container
        when Project
          if parsed.type == ContextToken::MERGE_REQUEST
            container.merge_requests.find_by(iid: iid) # rubocop:disable CodeReuse/ActiveRecord -- Single bounded lookup.
          else
            WorkItem.find_by(project_id: container.id, iid: iid) # rubocop:disable CodeReuse/ActiveRecord -- Single bounded lookup.
          end
        when Group
          WorkItem.find_by(namespace_id: container.id, project_id: nil, iid: iid) # rubocop:disable CodeReuse/ActiveRecord -- Single bounded lookup.
        end
      end

      def traversal_path(record)
        container = container_of(record)
        namespace = container.is_a?(Project) ? container.namespace : container
        namespace.traversal_path(with_organization: true)
      end

      def find_container(parsed)
        project = Project.find_by_full_path(parsed.path) unless parsed.container == :group
        return project if project || parsed.container == :project
        return unless parsed.type == ContextToken::WORK_ITEM

        Group.find_by_full_path(parsed.path)
      end

      def model_for(type)
        return ::Ci::Build if type == ContextToken::JOB
        return ::Ci::Pipeline if type == ContextToken::PIPELINE

        ::Authz::RedactionService::RESOURCE_CLASSES.fetch(ContextToken::REDACTION_TYPES.fetch(type))
      end

      def container_of(record)
        case record
        when ::Ci::Build, ::Ci::Pipeline, ::Commit, BranchRef then record.project
        else record.resource_parent
        end
      end

      # Each type takes the ability and fine-grained token permission of its REST endpoint.
      def readable?(record)
        container = container_of(record)
        return false unless container.present?

        case record
        when BranchRef then repository_readable?(container, :read_branch)
        when ::Commit then repository_readable?(container, :read_commit)
        when ::Ci::Pipeline then pipeline_readable?(record)
        else
          ability = case record
                    when MergeRequest then :read_merge_request
                    when ::Ci::Build then :read_build
                    else :read_work_item
                    end
          granular = ability == :read_build ? :read_job : ability

          Ability.allowed?(current_user, ability, record) && granular_scope_allowed?(granular, container)
        end
      end

      def repository_readable?(project, permission)
        Ability.allowed?(current_user, :read_code, project) && granular_scope_allowed?(permission, project)
      end

      def pipeline_readable?(pipeline)
        Ability.allowed?(current_user, :read_pipeline, pipeline) &&
          granular_scope_allowed?(:read_pipeline, pipeline.project)
      end

      def granular_scope_allowed?(permission, container)
        return true unless access_token

        @granular_scope_authorizations.fetch([permission, container.class, container.id]) do |key|
          @granular_scope_authorizations[key] = ::Authz::Tokens::AuthorizeGranularScopesService.new(
            boundaries: ::Authz::Boundary.for(container),
            permissions: permission,
            token: access_token
          ).execute.success?
        end
      end

      def summary(type, record)
        case type
        when ContextToken::MERGE_REQUEST then merge_request_summary(record)
        when ContextToken::JOB then job_summary(record)
        when ContextToken::PIPELINE then pipeline_summary(record)
        when ContextToken::BRANCH then branch_summary(record)
        when ContextToken::COMMIT then commit_summary(record)
        else work_item_summary(record)
        end
      end

      def job_summary(job)
        pipeline = job.pipeline
        merge_request = pipeline.merge_request
        merge_request = nil unless merge_request && readable?(merge_request)
        failure = job_failure(job, full_log: true)
        truncated = failure.delete(:truncated) || []
        container_paths(job.project).merge(
          id: job.id,
          name: job.name,
          status: job.status,
          stage: job.ci_stage&.name,
          failure_reason: (job.failure_reason if job.failed?),
          allow_failure: job.allow_failure,
          ref: job.ref,
          sha: job.sha,
          web_url: Gitlab::UrlBuilder.build(job),
          pipeline_id: pipeline.id,
          pipeline_status: pipeline.status,
          merge_request: merge_request && linked_summary(ContextToken::MERGE_REQUEST, merge_request),
          **failure,
          truncated: truncated
        )
      end

      def pipeline_summary(pipeline)
        truncated = []
        merge_request = pipeline.merge_request
        merge_request = nil unless merge_request && readable?(merge_request)

        container_paths(pipeline.project).merge(
          id: pipeline.id,
          status: pipeline.status,
          ref: pipeline.ref,
          sha: pipeline.sha,
          source: pipeline.source,
          web_url: Gitlab::UrlBuilder.build(pipeline),
          merge_request: merge_request && linked_summary(ContextToken::MERGE_REQUEST, merge_request, relation: nil),
          jobs: pipeline_jobs(pipeline, truncated),
          failed_jobs: pipeline_failed_jobs(pipeline, truncated),
          truncated: truncated
        )
      end

      def branch_summary(ref)
        truncated = []
        project = ref.project
        name = ref.branch.name
        merge_request = branch_merge_request(project, name)
        sha = ref.branch.dereferenced_target&.sha
        pipeline = sha && latest_readable_pipeline(project.latest_pipelines(ref: name, sha: sha))

        container_paths(project).merge(
          name: name,
          sha: sha,
          default_branch: project.default_branch == name,
          web_url: Gitlab::Routing.url_helpers.project_tree_url(project, name),
          merge_request: merge_request && linked_summary(ContextToken::MERGE_REQUEST, merge_request, relation: nil),
          pipeline_id: pipeline&.id,
          pipeline_status: pipeline&.status,
          failed_jobs: pipeline && pipeline_failed_jobs(pipeline, truncated),
          truncated: truncated
        )
      end

      def commit_summary(commit)
        truncated = []
        project = commit.project
        pipeline = latest_readable_pipeline(commit.pipelines)

        container_paths(project).merge(
          sha: commit.sha,
          title: commit.title,
          description: description(commit),
          author_name: commit.author_name,
          authored_date: commit.authored_date&.iso8601,
          web_url: Gitlab::UrlBuilder.build(commit),
          pipeline_id: pipeline&.id,
          pipeline_status: pipeline&.status,
          merge_requests: commit_merge_request_links(project, commit, truncated),
          changed_files: commit_changed_files(commit, truncated),
          truncated: truncated
        )
      end

      def merge_request_summary(merge_request)
        truncated = []

        container_paths(merge_request.project).merge(
          title: merge_request.title,
          state: merge_request.state,
          iid: merge_request.iid,
          web_url: Gitlab::UrlBuilder.build(merge_request),
          author: user_summary(merge_request.author),
          source_branch: merge_request.source_branch,
          target_branch: merge_request.target_branch,
          head_pipeline_status: head_pipeline_status(merge_request),
          merge_commit_sha: merge_request.merged_commit_sha,
          reviewers: user_summaries(:reviewers, merge_request.reviewers, truncated),
          linked_issues: linked_summaries(
            :linked_issues, ContextToken::WORK_ITEM, linked_work_items(merge_request), truncated
          ),
          description: description(merge_request),
          changed_files: changed_files(merge_request, truncated),
          failed_jobs: failed_jobs(merge_request, truncated),
          discussions: discussions(merge_request, truncated),
          truncated: truncated
        )
      end

      def work_item_summary(work_item)
        truncated = []

        container_paths(work_item.project || work_item.namespace).merge(
          title: work_item.title,
          state: work_item.state,
          iid: work_item.iid,
          work_item_type: work_item.issue_type,
          web_url: Gitlab::UrlBuilder.build(work_item),
          labels: label_titles(work_item, truncated),
          assignees: user_summaries(:assignees, work_item.assignees, truncated),
          milestone: work_item.milestone && { id: work_item.milestone.id, title: work_item.milestone.title },
          linked_merge_requests: linked_summaries(
            :linked_merge_requests, ContextToken::MERGE_REQUEST, linked_merge_requests(work_item), truncated
          ),
          description: description(work_item),
          discussions: discussions(work_item, truncated),
          truncated: truncated
        )
      end

      def capped(name, items, limit, truncated)
        truncated << name if items.size > limit
        items.first(limit)
      end

      def user_summaries(name, users, truncated)
        readable = users.order(:id).limit(MAX_RELATED_CANDIDATES).lazy # rubocop:disable CodeReuse/ActiveRecord -- Bounded, ordered query.
          .filter_map { |user| user_summary(user) }.first(MAX_USERS + 1)
        capped(name, readable, MAX_USERS, truncated)
      end

      def label_titles(work_item, truncated)
        titles = work_item.labels.order(:title).limit(MAX_LABELS + 1).pluck(:title) # rubocop:disable CodeReuse/ActiveRecord -- Bounded query.
        capped(:labels, titles, MAX_LABELS, truncated)
      end

      def linked_summaries(name, type, records, truncated)
        capped(name, records, MAX_RELATED_ITEMS, truncated).map { |record| linked_summary(type, record) }
      end

      def container_paths(container)
        return { namespace_path: container.full_path, project_path: nil } if container.is_a?(Namespace)

        { namespace_path: container.namespace.full_path, project_path: container.full_path }
      end

      def user_summary(user)
        return unless user && Ability.allowed?(current_user, :read_user, user)

        { id: user.id, username: user.username, name: user.name }
      end

      def head_pipeline_status(merge_request)
        readable_head_pipeline(merge_request)&.status
      end

      def readable_head_pipeline(merge_request)
        pipeline = merge_request.diff_head_pipeline
        pipeline if pipeline && pipeline_readable?(pipeline)
      end

      def description(record)
        record.description.to_s.truncate(MAX_DESCRIPTION).presence
      end

      # rubocop:disable CodeReuse/ActiveRecord -- Bounded, ordered queries.
      def changed_files(merge_request, truncated)
        return unless Ability.allowed?(current_user, :download_code, merge_request.project) &&
          granular_scope_allowed?(:download_code, merge_request.project)

        diff = merge_request.merge_request_diff
        return unless diff

        files = capped(:changed_files, diff.merge_request_diff_files.limit(MAX_CHANGED_FILES + 1).to_a,
          MAX_CHANGED_FILES, truncated)
        budgeted_diffs(truncated) { changed_file_summaries(diff, files) }
      end

      def budgeted_diffs(truncated)
        @diff_lines_left = MAX_DIFF_LINES
        summaries = yield
        truncated << :diffs if summaries.map { |file| file.delete(:diff_cut) }.any?
        summaries
      end

      # Takes the read_commit_diff check of the REST commit diff endpoint. Large diffs come back collapsed.
      def commit_changed_files(commit, truncated)
        return unless granular_scope_allowed?(:read_commit_diff, commit.project)

        diffs = commit.raw_diffs(max_files: MAX_CHANGED_FILES, expanded: false)
        files = diffs.to_a
        truncated << :changed_files if diffs.overflow? || files.size > MAX_CHANGED_FILES
        budgeted_diffs(truncated) { files.first(MAX_CHANGED_FILES).map { |file| changed_file(file) } }
      rescue StandardError => error
        ::Gitlab::ErrorTracking.track_exception(error, commit_sha: commit.sha)
        nil
      end

      # Opens an externally stored diff once for all files, without the temp copy that `utf8_diff` leaves.
      def changed_file_summaries(diff, files)
        diff.opening_external_diff { files.map { |file| changed_file(file) } }
      rescue StandardError => error
        ::Gitlab::ErrorTracking.track_exception(error, merge_request_diff_id: diff.id)
        files.map { |file| changed_file(file, with_lines: false) }
      end

      def changed_file(file, with_lines: true)
        status = file_status(file)
        summary = { path: file.new_path, old_path: (file.old_path if status == 'R'), status: status }
        return summary unless with_lines && status != 'D'

        text = ::Gitlab::EncodingHelper.encode_utf8(file.diff.to_s).to_s
        summary.merge(lines: changed_lines(file, text), **diff_excerpt(file, text)).compact
      end

      def diff_excerpt(file, text)
        return {} if file.generated || file.too_large? || file.try(:binary?)
        return {} if ::Gitlab::Git::Diff.has_binary_notice?(text)

        lines = text.lines.reject { |line| line.start_with?('\\') }
        keep = [lines.size, MAX_FILE_DIFF_LINES, @diff_lines_left].min
        return { diff_cut: lines.any? } if keep <= 0

        @diff_lines_left -= keep
        excerpt = lines.first(keep).join.rstrip
        return { diff: excerpt } if keep == lines.size

        { diff: "#{excerpt}\n... #{lines.size - keep} more diff lines", diff_cut: true }
      end

      def file_status(file)
        return 'A' if file.new_file
        return 'D' if file.deleted_file
        return 'R' if file.renamed_file

        'M'
      end

      def changed_lines(file, diff)
        changed = changed_positions(file, diff)
        return unless changed

        ranges = changed.chunk_while { |a, b| b == a + 1 }
          .map { |run| run.one? ? run.first.to_s : "#{run.first}-#{run.last}" }
        return ranges if ranges.size <= MAX_LINE_RANGES

        ranges.first(MAX_LINE_RANGES) + ["+#{ranges.size - MAX_LINE_RANGES} more"]
      end

      # Only the parse is rescued per file; a read error reaches `changed_file_summaries` and is tracked once.
      def changed_positions(file, diff)
        ::Gitlab::Diff::Parser.new.parse(diff.lines)
          .select { |line| line.added? || line.removed? }.map(&:new_pos).uniq
      rescue StandardError => error
        ::Gitlab::ErrorTracking.track_exception(error, merge_request_diff_id: file.try(:merge_request_diff_id),
          relative_order: file.try(:relative_order), path: file.new_path)
        nil
      end

      def failed_jobs(merge_request, truncated)
        pipeline = readable_head_pipeline(merge_request)
        pipeline_failed_jobs(pipeline, truncated) if pipeline
      end

      # Takes the checks of the REST pipeline jobs endpoint: read_build, and read_pipeline_job for a token.
      def jobs_readable?(pipeline)
        Ability.allowed?(current_user, :read_build, pipeline) &&
          granular_scope_allowed?(:read_pipeline_job, pipeline.project)
      end

      def pipeline_jobs(pipeline, truncated)
        return unless jobs_readable?(pipeline)

        jobs = pipeline.builds.latest.preload(:ci_stage, :project).order(:stage_idx, :id)
          .limit(MAX_PIPELINE_JOBS + 1).to_a
        capped(:jobs, jobs, MAX_PIPELINE_JOBS, truncated).map do |job|
          { name: job.name, stage: job.ci_stage&.name, status: job.status, allow_failure: job.allow_failure,
            web_url: Gitlab::UrlBuilder.build(job) }
        end
      end

      def pipeline_failed_jobs(pipeline, truncated)
        return unless jobs_readable?(pipeline)

        jobs = pipeline.builds.latest.failed.preload(:ci_stage, :project).order(:allow_failure, :id)
          .limit(MAX_FAILED_JOBS + 1).to_a
        capped(:failed_jobs, jobs, MAX_FAILED_JOBS, truncated).each_with_index.map do |job, index|
          {
            name: job.name,
            stage: job.ci_stage&.name,
            failure_reason: job.failure_reason,
            allow_failure: job.allow_failure,
            web_url: Gitlab::UrlBuilder.build(job),
            **(index < MAX_TRACED_JOBS ? job_failure(job) : {})
          }.compact
        end
      end

      def job_failure(job, full_log: false)
        JobFailure.new(
          job, current_user,
          read_log: granular_scope_allowed?(:read_job, job.project),
          read_tests: granular_scope_allowed?(:read_pipeline_test_report, job.project),
          full_log: full_log
        ).execute
      rescue StandardError => error
        ::Gitlab::ErrorTracking.track_exception(error, job_id: job.id)
        {}
      end

      def discussions(record, truncated)
        return unless granular_scope_allowed?(discussion_permission(record), container_of(record))

        notes = record.notes.user.preload(:author, :project).order(id: :desc)
          .limit(MAX_NOTE_CANDIDATES + 1).to_a
        readable = notes.first(MAX_NOTE_CANDIDATES).lazy.select { |note| note.readable_by?(current_user) }
          .first(MAX_NOTES + 1)
        truncated << :discussions if readable.size > MAX_NOTES || notes.size > MAX_NOTE_CANDIDATES
        readable.first(MAX_NOTES).reverse.map { |note| note_summary(note) }
      end
      # rubocop:enable CodeReuse/ActiveRecord

      def discussion_permission(record)
        return :read_merge_request_discussion if record.is_a?(MergeRequest)

        record.epic_work_item? ? :read_epic_discussion : :read_issue_discussion
      end

      def note_summary(note)
        entry = {
          author: note.author&.username,
          created_at: note.created_at.to_date.iso8601,
          body: note.note.to_s.truncate(MAX_NOTE_CHARS)
        }
        entry[:resolved] = note.resolved? if note.resolvable?
        position = note.try(:position)
        return entry unless position

        entry[:path] = position.new_path || position.old_path
        entry[:line] = position.new_line || position.old_line if position.on_text?
        entry
      end

      # rubocop:disable CodeReuse/ActiveRecord -- Bounded, ordered queries that preload for readable? and linked_summary.
      def linked_work_items(merge_request)
        ids = merge_request.merge_request_closing_issues.order(:issue_id).limit(MAX_RELATED_CANDIDATES).pluck(:issue_id)

        WorkItem.id_in(ids).order(:id)
          .preload(project: [:namespace, :route], namespace: :route)
          .lazy.select { |work_item| readable?(work_item) }.first(MAX_RELATED_ITEMS + 1)
      end

      # The finder applies the caller's merge request visibility; readable? adds the token check. The source
      # project filter keeps out fork merge requests whose source branch has the same name.
      def branch_merge_request(project, name)
        candidates = MergeRequestsFinder
          .new(current_user, project_id: project.id, source_project_id: project.id, source_branch: name)
          .execute.reorder(updated_at: :desc, id: :desc).limit(MAX_RELATED_CANDIDATES)
          .preload(target_project: [:namespace, :route]).to_a
          .select { |merge_request| readable?(merge_request) }

        candidates.find(&:opened?) || candidates.first
      end

      # Takes the read_commit_merge_request check of the REST commit merge requests endpoint.
      def commit_merge_request_links(project, commit, truncated)
        return unless granular_scope_allowed?(:read_commit_merge_request, project)

        capped(:merge_requests, commit_merge_requests(project, commit), MAX_RELATED_ITEMS, truncated)
          .map { |merge_request| linked_summary(ContextToken::MERGE_REQUEST, merge_request, relation: nil) }
      end

      def commit_merge_requests(project, commit)
        MergeRequestsFinder.new(current_user, project_id: project.id, commit_sha: commit.sha)
          .execute.reorder(:id).limit(MAX_RELATED_CANDIDATES)
          .preload(target_project: [:namespace, :route])
          .lazy.select { |merge_request| readable?(merge_request) }.first(MAX_RELATED_ITEMS + 1)
      end

      # Prefers the newest pipeline that ran over a skipped one, as the branch view does.
      def latest_readable_pipeline(pipelines)
        readable = pipelines.order(id: :desc).limit(MAX_PIPELINE_CANDIDATES).preload(project: [:namespace, :route])
          .to_a.select { |pipeline| pipeline_readable?(pipeline) }

        readable.find { |pipeline| !pipeline.skipped? } || readable.first
      end

      def linked_merge_requests(work_item)
        ids = work_item.merge_request_closing_issues.order(:merge_request_id).limit(MAX_RELATED_CANDIDATES)
          .pluck(:merge_request_id)

        MergeRequest.id_in(ids).order(:id)
          .preload(target_project: [:namespace, :route])
          .lazy.select { |merge_request| readable?(merge_request) }.first(MAX_RELATED_ITEMS + 1)
      end
      # rubocop:enable CodeReuse/ActiveRecord

      def linked_summary(type, record, relation: LINK_RELATION)
        {
          type: type,
          id: record.id.to_s,
          token: resolved_token(type, record.id),
          relation: relation,
          iid: record.iid,
          project_path: record.project&.full_path,
          title: record.title
        }.tap { |summary| summary.delete(:relation) unless relation }
      end
    end
  end
end
