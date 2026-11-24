# frozen_string_literal: true

# Gitlab::Git::CommitStats counts the additions, deletions, and total changes
# in a commit.
module Gitlab
  module Git
    class CommitStats
      include Gitlab::Git::WrapsGitalyErrors

      TIMED_OUT_EXPIRY = 10.minutes

      attr_reader :id, :additions, :deletions, :total, :files

      # Instantiate a CommitStats object
      #
      # Gitaly migration: https://gitlab.com/gitlab-org/gitaly/issues/323
      def initialize(repo, commit)
        @id = commit.id

        additions, deletions, files = ensure_stats_format(repo)

        @additions = additions.to_i
        @deletions = deletions.to_i
        @files = files.to_i
        @total = @additions + @deletions
      end

      def ensure_stats_format(repo)
        cached_stats = fetch_stats(repo)

        if cached_stats.length == 2
          Rails.cache.delete(cache_key(repo))
          cached_stats = fetch_stats(repo)
        end

        cached_stats
      end

      def fetch_stats(repo)
        Rails.cache.fetch(cache_key(repo)) do
          stats = gitaly_commit_stats(repo)

          [stats.additions, stats.deletions, stats.files]
        end
      end

      private

      # Rails.cache.fetch caches nothing when the block raises, so timeouts are
      # remembered separately to stop retries paying the full Gitaly deadline.
      def gitaly_commit_stats(repo)
        unless repo.container.is_a?(::Project) && Feature.enabled?(:commit_stats_failure_handling, repo.container)
          return commit_stats_from_gitaly(repo)
        end

        timed_out_key = timed_out_cache_key(repo)

        if Rails.cache.exist?(timed_out_key)
          raise Gitlab::Git::CommandTimedOut,
            "commit stats for #{@id} timed out within the last #{TIMED_OUT_EXPIRY.inspect}"
        end

        begin
          commit_stats_from_gitaly(repo)
        rescue Gitlab::Git::CommandTimedOut
          Rails.cache.write(timed_out_key, true, expires_in: TIMED_OUT_EXPIRY)
          raise
        end
      end

      def commit_stats_from_gitaly(repo)
        wrapped_gitaly_errors { repo.gitaly_commit_client.commit_stats(@id) }
      end

      def cache_key(repo)
        "commit_stats:#{repo.gl_project_path}:#{@id}"
      end

      def timed_out_cache_key(repo)
        "#{cache_key(repo)}:timed_out"
      end
    end
  end
end
