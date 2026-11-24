# frozen_string_literal: true

module ComplianceManagement
  module ComplianceReport
    class CommitLoader
      COMMITS_PER_PROJECT = 1024
      COMMIT_BATCH_SIZE = 100
      STREAMING_CHUNK_SIZE = 500

      def initialize(group, current_user, filter_params = {})
        raise ArgumentError, 'The group is a required argument' if group.blank?
        raise ArgumentError, 'The user is a required argument' if current_user.blank?

        @current_user = current_user
        @group = group
        @filters = filter_params
        @count = 0
        @from = @filters[:from] || 1.month.ago
        @to = @filters[:to] || Time.current
      end

      attr_reader :count

      def find_each(&block)
        mr_commits = build_mr_commits_hash

        # Stream process projects one by one to avoid memory exhaustion
        # Each project's commits are processed in chronological chunks
        projects.inc_routes.find_each do |project|
          process_project_streaming(project, mr_commits, &block)
        end
      end

      private

      attr_reader :current_user, :group, :filters, :from, :to

      def build_mr_commits_hash
        mr_commits = Hash.new { |h, k| h[k] = [] }
        merge_requests.find_each.each_with_object(mr_commits) do |mr, result|
          mr.commit_shas.each { |sha| result[sha] << mr }

          result[mr.squash_commit_sha] << mr if mr.squash_commit_sha?
          result[mr.merge_commit_sha] << mr if mr.merge_commit_sha?
        end
      end

      def process_project_streaming(project, mr_commits, &block)
        commits_for_project = 0
        chunk_rows = []

        while commits_for_project < COMMITS_PER_PROJECT
          batch = batch_of_commits_for_project(project, commits_for_project, COMMIT_BATCH_SIZE)
          break if batch.empty?

          batch.each do |commit|
            process_commit_to_chunk(commit, mr_commits, chunk_rows)
            commits_for_project += 1
            break if commits_for_project == COMMITS_PER_PROJECT
          end

          # Process and stream chunk when it gets large enough or when we're done with batches
          if chunk_rows.size >= STREAMING_CHUNK_SIZE || batch.count < COMMIT_BATCH_SIZE
            stream_chunk_with_user_lookup(chunk_rows, &block)
            chunk_rows = []
          end

          break if batch.count < COMMIT_BATCH_SIZE
        end

        stream_chunk_with_user_lookup(chunk_rows, &block) unless chunk_rows.empty?
      end

      def process_commit_to_chunk(commit, mr_commits, chunk_rows)
        mrs = mr_commits[commit.sha]

        if mrs.present?
          mrs.each do |mr|
            chunk_rows << CsvRow.new(commit, current_user, from, to, merge_request: mr)
            @count += 1
          end
        else
          chunk_rows << CsvRow.new(commit, current_user, from, to)
          @count += 1
        end
      end

      def stream_chunk_with_user_lookup(chunk_rows, &block)
        return if chunk_rows.empty?

        committer_emails = chunk_rows.filter_map do |row|
          row.commit&.committer_email.presence
        end.uniq

        committer_users = batch_lookup_users(committer_emails)

        sorted_chunk = sort_rows_deterministically(chunk_rows)

        sorted_chunk.each do |row|
          row.committer_users = committer_users
          yield(row)
        end
      end

      def batch_lookup_users(emails)
        return {} if emails.empty?

        # rubocop:disable CodeReuse/ActiveRecord -- Required for performance optimization to avoid N+1 queries
        users = User.by_any_email(emails, confirmed: false).includes(:emails)
        # rubocop:enable CodeReuse/ActiveRecord

        email_to_user = {}
        emails.each do |email|
          user = users.find { |u| u.any_email?(email) }
          email_to_user[email] = user if user
        end

        email_to_user
      end

      def sort_rows_deterministically(rows)
        rows.sort do |a, b|
          date_comparison = b.commit.committed_date <=> a.commit.committed_date
          date_comparison == 0 ? b.sha <=> a.sha : date_comparison
        end
      end

      def merge_requests
        MergeRequestsFinder
          .new(current_user, merge_request_finder_options)
          .execute
          .preload_author
          .preload_approved_by_users
          .preload_target_project_with_namespace
          .preload_project_and_latest_diff
          .preload_metrics([:merged_by])
      end

      def merge_request_finder_options
        {
          group_id: group.id,
          state: 'merged',
          merge_commit_sha: filters[:commit_sha],
          include_subgroups: true,
          merged_after: merged_after
        }
      end

      # A specific commit can be older than the report window, so only bound the full report.
      def merged_after
        from if filters[:commit_sha].blank?
      end

      def projects
        GroupProjectsFinder.new(
          group: group,
          current_user: current_user,
          options: { include_subgroups: true }
        ).execute
      end

      def batch_of_commits_for_project(project, offset, limit)
        if filters[:commit_sha].present?
          [
            project.repository.commit_by(oid: filters[:commit_sha])
          ].compact
        else
          project.repository.commits(
            nil,
            offset: offset,
            limit: limit,
            after: from,
            before: to,
            order: 'default'
          )
        end
      rescue ::Gitlab::Git::Repository::NoRepository
        []
      end
    end
  end
end
