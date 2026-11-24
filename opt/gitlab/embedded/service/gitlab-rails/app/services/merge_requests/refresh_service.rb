# frozen_string_literal: true

module MergeRequests
  class RefreshService < MergeRequests::BaseService
    include Gitlab::Utils::StrongMemoize

    attr_reader :push

    # Staggered delays for auto-merge worker enqueue.
    # Each MR gets a delay of index * INTERVAL seconds, spaced 3 seconds apart
    # (0s, 3s, 6s, ..., 57s) to avoid workers from the same or overlapping push
    # events landing at the same time. Capped at 20 MRs per push event; remaining
    # MRs are picked up in subsequent rounds as merges trigger new pushes.
    AUTO_MERGE_DELAY_INTERVAL = 3
    AUTO_MERGE_BATCH_LIMIT = 20

    def execute(oldrev, newrev, ref)
      @push = Gitlab::Git::Push.new(@project, oldrev, newrev, ref)
      return true unless @push.branch_push?

      refresh_merge_requests!
    end

    # Counts from {#execute}, for the worker's done log. They size the bound on inline diff
    # reloads: https://gitlab.com/gitlab-org/gitlab/-/work_items/635705
    #
    # @return [Hash{Symbol => Integer, Float}] empty when the push isn't a branch push
    def refresh_stats
      @refresh_stats ||= {}
    end

    private

    def refresh_merge_requests!
      # n + 1: https://gitlab.com/gitlab-org/gitlab-foss/issues/60289
      Gitlab::GitalyClient.allow_n_plus_1_calls { find_new_commits }
      refresh_stats[:pushed_commits] = @commits.size

      # Be sure to close outstanding MRs before reloading them to avoid generating an
      # empty diff during a manual merge
      close_upon_missing_source_branch_ref

      post_merge_manually_merged

      link_forks_lfs_objects

      reload_merge_requests

      merge_requests_for_source_branch.each do |mr|
        outdate_suggestions(mr)
        abort_auto_merges(mr)
        mark_pending_todos_done(mr)
      end

      abort_ff_merge_requests_with_auto_merges

      cache_merge_requests_closing_issues

      merge_requests_for_source_branch.each do |mr|
        # Leave a system note if a branch was deleted/added
        comment_mr_branch_presence_changed(mr) if branch_added_or_removed?

        notify_about_push(mr)

        mark_mr_as_draft_from_commits(mr)
        merge_request_activity_counter.track_mr_including_ci_config(user: mr.author, merge_request: mr)
      end

      execute_async_workers

      true
    end

    def branch_added_or_removed?
      strong_memoize(:branch_added_or_removed) do
        @push.branch_added? || @push.branch_removed?
      end
    end

    def close_upon_missing_source_branch_ref
      # MergeRequest#reload_diff ignores not opened MRs. This means it won't
      # create an `empty` diff for `closed` MRs without a source branch, keeping
      # the latest diff state as the last _valid_ one.
      merge_requests_for_source_branch.reject(&:source_branch_exists?).each do |mr|
        Gitlab::AppLogger.info(
          message: 'Closing merge request due to missing source branch',
          merge_request_id: mr.id,
          merge_request_iid: mr.iid,
          project_id: mr.project_id,
          source_branch: mr.source_branch
        )

        MergeRequests::CloseService
          .new(project: mr.target_project, current_user: @current_user)
          .execute(mr)
      end
    end

    # Collect open merge requests that target same branch we push into
    # and close if push to master include last commit from merge request
    # We need this to close(as merged) merge requests that were merged into
    # target branch manually
    def post_merge_manually_merged
      mark_manually_merged(
        Gitlab::MergeRequests::ManualMergeDetector
          .new(project: @project, branch_name: @push.branch_name, commits: @commits)
          .execute
      )
    end

    # retryable: false for the emptied diff path, which is best effort: errors are only tracked,
    # so the rest of the refresh still runs.
    def mark_manually_merged(merge_commit_sha_by_merge_request, retryable: true)
      return if merge_commit_sha_by_merge_request.empty?

      commits_by_sha = merge_commits_by_sha(merge_commit_sha_by_merge_request.values, retryable: retryable)

      # A source branch push can land a merge request's head on its target branch.
      merge_source_resolvers = Hash.new do |resolvers, branch_name|
        resolvers[branch_name] = Gitlab::MergeRequests::MergeSourceResolver
          .new(project: @project, branch_name: branch_name, newrev: @push.newrev)
      end
      first_error = nil

      merge_commit_sha_by_merge_request.each do |merge_request, sha|
        merge_request.merge_commit_sha = sha
        merge_request.merged_commit_sha = sha

        source = source_merge_request(merge_source_resolvers[merge_request.target_branch], sha) ||
          commits_by_sha[sha]

        MergeRequests::PostMergeService
          .new(project: merge_request.target_project, current_user: @current_user)
          .execute(merge_request, source)
      rescue StandardError => e
        # One failing merge request must not leave the rest of the batch
        # unprocessed. When retryable, re-raised after the loop so the worker retries
        # the ones still open; an MR that failed after mark_as_merged is not retried.
        Gitlab::ErrorTracking.track_exception(
          e,
          { merge_request_id: merge_request.id, project_id: @project.id },
          { merged_manually_detection: retryable ? 'post_merge_batch' : 'emptied_diff_post_merge' }
        )
        first_error ||= e
      end

      raise first_error if first_error && retryable
    end

    # The commits only credit the merged state event, so on the best-effort path a failed
    # lookup falls back to none instead of aborting the refresh.
    def merge_commits_by_sha(shas, retryable:)
      @project.repository.commits_by(oids: shas.compact.uniq).index_by(&:id)
    rescue StandardError => e
      raise if retryable

      Gitlab::ErrorTracking.track_exception(
        e,
        { project_id: @project.id },
        { merged_manually_detection: 'emptied_diff_merge_commits' }
      )
      {}
    end

    def source_merge_request(merge_source_resolver, sha)
      return merge_source_resolver.resolve(sha) if Feature.enabled?(:merge_source_resolver, @project)

      # Only the merged MRs without the event source would be considered
      # to avoid associating it with other MRs that we may have marked as merged here.
      MergeRequestsFinder.new(
        @current_user,
        project_id: @project.id,
        merged_without_event_source: true,
        state: 'merged',
        sort: 'merged_at',
        commit_sha: sha
      ).execute.first
    end

    # Link LFS objects that exists in forks but does not exists in merge requests
    # target project
    def link_forks_lfs_objects
      return unless @push.branch_updated?

      merge_requests_for_forks.find_each do |mr|
        LinkLfsObjectsService
          .new(project: mr.target_project)
          .execute(mr, oldrev: @push.oldrev, newrev: @push.newrev)
      end
    end

    # Refresh merge request diff if we push to source or target branch of merge request
    # Note: we should update merge requests from forks too
    def reload_merge_requests
      merge_requests = @project.merge_requests.opened
        .by_source_or_target_branch(@push.branch_name)
        .preload_project_and_latest_diff
        .preload_merge_data(@project)

      merge_requests_from_forks = merge_requests_for_forks
        .preload_project_and_latest_diff
        .preload_merge_data(@project)

      merge_requests_array = merge_requests.to_a + merge_requests_from_forks.to_a
      filtered_merge_requests = filter_merge_requests(merge_requests_array)
      diffs_before_reload = filtered_merge_requests.index_with(&:merge_request_diff)

      recheck_merge_requests_batched(filtered_merge_requests)

      mark_manually_merged(merged_by_emptied_diff(diffs_before_reload), retryable: false)

      # Upcoming method calls need the refreshed version of
      # @source_merge_requests diffs (for MergeRequest#commit_shas for instance).
      merge_requests_for_source_branch(reload: true)
    end

    def recheck_merge_requests_batched(filtered_merge_requests)
      source_branch_or_force_pushed_mrs = []
      all_mr_ids = []
      diff_ids_to_reload = batched_diff_ids_to_reload(filtered_merge_requests)

      filtered_merge_requests.each do |merge_request|
        all_mr_ids << merge_request.id

        if branch_and_project_match?(merge_request)
          reload_diff_and_record(merge_request, :source_branch)
          schedule_duo_code_review(merge_request)
          source_branch_or_force_pushed_mrs << merge_request
        elsif @push.force_push?
          reload_diff_and_record(merge_request, :force_push)
          source_branch_or_force_pushed_mrs << merge_request
        elsif diff_ids_to_reload.include?(merge_request.merge_request_diff.id)
          reload_diff_and_record(merge_request, :target_branch)
        end
      end

      record_reload_stats(filtered_merge_requests.size)

      MergeRequest.batch_mark_as_unchecked(all_mr_ids, mrs_to_trigger: source_branch_or_force_pushed_mrs)

      # Clear existing merge error if the push were directed at the
      # source branch. Clearing the error when the target branch
      # changes will hide the error from the user.
      MergeRequest.batch_clear_merge_error(source_branch_or_force_pushed_mrs.map(&:id))

      enqueue_auto_merge_for_unchecked(filtered_merge_requests)
    end

    # Catches a merge outside GitLab that post_merge_manually_merged couldn't match because
    # the stored diff head was stale: reloading empties the diff once the head is on the target.
    # Returns merge request => merge commit SHA.
    def merged_by_emptied_diff(diffs_before_reload)
      return {} unless Feature.enabled?(:detect_manual_merge_by_emptied_diff, @project)

      diffs_before_reload.each_with_object({}) do |(merge_request, previous_diff), merged|
        merge_commit_sha = Gitlab::MergeRequests::EmptiedDiffMergeDetector
          .new(merge_request: merge_request, previous_diff: previous_diff)
          .execute
        next unless merge_commit_sha

        keep_as_latest_diff(merge_request, previous_diff)
        merged[merge_request] = merge_commit_sha
      rescue StandardError => e
        # Best effort: a failure leaves this merge request open, as before this detection, and
        # must not abort the refresh for the others. A retry can't re-detect it: its diff is empty.
        Gitlab::ErrorTracking.track_exception(
          e,
          { merge_request_id: merge_request.id, project_id: @project.id },
          { merged_manually_detection: 'emptied_diff' }
        )
      end
    end

    # The reload's empty diff has no changes to show, and PostMergeService deletes the files of
    # every diff that isn't the latest, so the diff with the changes becomes the latest again.
    def keep_as_latest_diff(merge_request, diff)
      merge_request.update_column(:latest_merge_request_diff_id, diff.id)
      # The reload loaded the association, which returns the newest diff whatever the column says.
      merge_request.association(:merge_request_diff).reset
    end

    def enqueue_auto_merge_for_unchecked(merge_requests)
      auto_merge_mrs = merge_requests.select(&:auto_merge_enabled?)
      return if auto_merge_mrs.empty?

      auto_merge_mrs.first(AUTO_MERGE_BATCH_LIMIT).each_with_index do |mr, index|
        delay = index * AUTO_MERGE_DELAY_INTERVAL
        AutoMergeProcessWorker.perform_in(delay.seconds, { 'merge_request_id' => mr.id })
      end
    end

    # Reloads the diff and adds it to the count and duration of the given refresh path.
    #
    # @param merge_request [MergeRequest]
    # @param path [Symbol] :source_branch, :target_branch or :force_push
    # @return [void]
    def reload_diff_and_record(merge_request, path)
      start = ::Gitlab::Metrics::System.monotonic_time
      merge_request.reload_diff(current_user)

      reload_counts[path] += 1
      reload_durations[path] += ::Gitlab::Metrics::System.monotonic_time - start
      nil
    end

    # Adds the reload counts and durations for each path to {#refresh_stats}.
    #
    # @param considered_count [Integer] open merge requests the push could reload
    # @return [void]
    def record_reload_stats(considered_count)
      refresh_stats.merge!(
        merge_requests_considered: considered_count,
        source_branch_reloads: reload_counts[:source_branch],
        source_branch_reload_duration_s: reload_durations[:source_branch].round(6),
        target_branch_reloads: reload_counts[:target_branch],
        target_branch_reload_duration_s: reload_durations[:target_branch].round(6),
        force_push_reloads: reload_counts[:force_push],
        force_push_reload_duration_s: reload_durations[:force_push].round(6)
      )
      nil
    end

    def reload_counts
      @reload_counts ||= Hash.new(0)
    end

    def reload_durations
      @reload_durations ||= Hash.new(0.0)
    end

    # A merge request the push only reaches through its target branch needs its diff
    # rebuilt when the push carries commits that diff already contains - the stacked
    # case. Resolving the whole set in one query, rather than asking each merge
    # request in turn, keeps that cost independent of the merge request count.
    def batched_diff_ids_to_reload(filtered_merge_requests)
      # Force pushes reload every diff unconditionally, so nothing needs looking up.
      return Set.new if @push.force_push?

      diff_ids = filtered_merge_requests
        .reject { |merge_request| branch_and_project_match?(merge_request) }
        .filter_map { |merge_request| merge_request.merge_request_diff.id }

      MergeRequestDiff.ids_including_any_commits(diff_ids, push_commit_ids, project: @project)
    end

    def push_commit_ids
      @push_commit_ids ||= @commits.map(&:id)
    end

    def branch_and_project_match?(merge_request)
      merge_request.source_project == @project &&
        merge_request.source_branch == @push.branch_name
    end

    def outdate_suggestions(merge_request)
      outdate_service.execute(merge_request)
    end

    def outdate_service
      @outdate_service ||= Suggestions::OutdateService.new
    end

    def abort_auto_merges?(merge_request)
      merge_request.merge_params.with_indifferent_access[:sha] != @push.newrev
    end

    def abort_auto_merges(merge_request)
      return unless abort_auto_merges?(merge_request)

      learn_more_url = Rails.application.routes.url_helpers.help_page_url(
        'ci/pipelines/merge_trains.md',
        anchor: 'merge-request-dropped-from-the-merge-train'
      )

      abort_auto_merge(merge_request, "the source branch was updated. [Learn more](#{learn_more_url}).")
    end

    def abort_ff_merge_requests_with_auto_merges
      return unless @project.ff_merge_must_be_possible?

      # Aborting exists because a moved target branch normally leaves the author with a
      # manual rebase that a pending auto-merge cannot perform for them. With automatic
      # rebase before merge, that rebase happens as part of the merge, so the pending
      # auto-merge stays valid.
      if @project.project_setting.automatic_rebase_enabled? &&
          Feature.enabled?(:retain_auto_merge_with_automatic_rebase, @project)
        return
      end

      merge_requests_with_auto_merge_enabled_to(@push.branch_name).each do |merge_request|
        unless merge_request.auto_merge_strategy == AutoMergeService::STRATEGY_MERGE_WHEN_CHECKS_PASS
          next
        end

        next unless merge_request.should_be_rebased?

        abort_auto_merge_with_todo(merge_request, 'the target branch was updated.')
      end
    end

    def merge_requests_with_auto_merge_enabled_to(target_branch)
      @project
        .merge_requests
        .by_target_branch(target_branch)
        .with_auto_merge_enabled
    end

    def mark_pending_todos_done(merge_request)
      todo_service.merge_request_push(merge_request, @current_user)
    end

    def find_new_commits
      if @push.branch_added?
        @commits = []

        merge_request = merge_requests_for_source_branch.first
        return unless merge_request

        begin
          # Since any number of commits could have been made to the restored branch,
          # find the common root to see what has been added.
          common_ref = @project.repository.merge_base(merge_request.diff_head_sha, @push.newrev)
          # If a commit no longer exists in this repo, the call may raise an error.
          @commits = @project.repository.commits_between(common_ref, @push.newrev) if common_ref
        rescue StandardError
        end
      elsif @push.branch_removed?
        # No commits for a deleted branch.
        @commits = []
      else
        @commits = @project.repository.commits_between(@push.oldrev, @push.newrev)
      end
    end

    # Add comment about branches being deleted or added to merge requests
    def comment_mr_branch_presence_changed(merge_request)
      presence = @push.branch_added? ? :add : :delete

      SystemNoteService.change_branch_presence(
        merge_request, merge_request.project, @current_user,
        :source, @push.branch_name, presence)
    end

    # Add comment about pushing new commits to merge requests and send notification emails
    #
    def notify_about_push(merge_request)
      return unless @commits.present?

      mr_commit_ids = Set.new(merge_request.commit_shas)

      new_commits, existing_commits = @commits.partition do |commit|
        mr_commit_ids.include?(commit.id)
      end

      SystemNoteService.add_commits(
        merge_request, merge_request.project,
        @current_user, new_commits,
        existing_commits, @push.oldrev
      )

      new_commits_data, total_new = prepare_commits_for_notification(new_commits)
      existing_commits_data, total_existing = prepare_commits_for_notification(existing_commits, first_and_last_only: true)

      MergeRequests::Refresh::NotifyAboutPushWorker.perform_async(
        merge_request.id,
        @current_user.id,
        new_commits_data,
        total_new,
        existing_commits_data,
        total_existing
      )
    end

    def mark_mr_as_draft_from_commits(merge_request)
      return unless @commits.present?

      commit_shas = merge_request.commit_shas

      draft_commit = @commits.detect do |commit|
        commit.draft? && commit_shas.include?(commit.sha)
      end

      if draft_commit && !merge_request.draft?
        merge_request.update(title: merge_request.draft_title)
        SystemNoteService.add_merge_request_draft_from_commit(
          merge_request,
          merge_request.project,
          @current_user,
          draft_commit
        )
      end
    end

    # If the merge requests closes any issues, save this information in the
    # `MergeRequestIssue` model (as a performance optimization).
    #
    # Only open merge requests are considered: `persist_merge_request_issues!`
    # is a no-op for closed and merged merge requests, so loading them here is
    # wasted work when a source branch is shared by many such merge requests.
    # rubocop: disable CodeReuse/ActiveRecord
    def cache_merge_requests_closing_issues
      @project.merge_requests.opened.where(source_branch: @push.branch_name).find_each do |merge_request|
        merge_request.persist_merge_request_issues!(@current_user)
      end
    end
    # rubocop: enable CodeReuse/ActiveRecord

    def filter_merge_requests(merge_requests)
      merge_requests.uniq.select(&:source_project)
    end

    def merge_requests_for_source_branch(reload: false)
      @source_merge_requests = nil if reload
      @source_merge_requests ||= merge_requests_for(@push.branch_name)
    end

    def merge_requests_for_forks
      @merge_requests_for_forks ||=
        MergeRequest
        .opened
        .from_project(project)
        .from_source_branches(@push.branch_name)
        .from_fork
    end

    def schedule_duo_code_review(merge_request)
      # Overridden in EE
    end

    def execute_async_workers
      MergeRequests::Refresh::WebHooksWorker.perform_async(
        @project.id,
        @current_user.id,
        @push.oldrev,
        @push.newrev,
        @push.ref
      )

      MergeRequests::Refresh::PipelineWorker.perform_async(
        @project.id,
        @current_user.id,
        @push.oldrev,
        @push.newrev,
        @push.ref,
        params.slice(:push_options, :gitaly_context).as_json # ensure sidekiq-compatible hash argument
      )
    end

    def prepare_commits_for_notification(commits, first_and_last_only: false)
      total_count = commits.count
      return [[], 0] if total_count == 0

      commits_to_process = if first_and_last_only && total_count > 2
                             [commits.first, commits.last]
                           else
                             commits.first(NotificationService::NEW_COMMIT_EMAIL_DISPLAY_LIMIT)
                           end

      commit_data = commits_to_process.map do |commit|
        { 'short_id' => commit.short_id, 'title' => commit.title }
      end

      [commit_data, total_count]
    end
  end
end

MergeRequests::RefreshService.prepend_mod_with('MergeRequests::RefreshService')
