# frozen_string_literal: true

module Gitlab
  module Ci
    # Cache hits return a Commit containing only FIELDS for CI job hook payloads.
    # Author lookup stays current; other serialized commit fields are unavailable.
    #
    # A commit SHA is content-addressed, so cached metadata for a SHA matches
    # what Gitaly returns for it for as long as the object exists. Accepted
    # residual: after `RewriteHistory` and a subsequent gc prune, an orphaned
    # SHA stops resolving in Gitaly while a cached entry still would for at
    # most TTL. Such an entry exists only because an earlier delivery for the
    # same SHA already sent the same metadata to the same recipients.
    class BuildHookCommitCache
      TTL = 10.minutes
      MAX_BYTES = 64.kilobytes
      FIELDS = %i[id message author_name author_email].freeze

      def initialize(project, sha)
        @project = project
        @sha = sha
        @store = Gitlab::Redis::RepositoryCache.cache_store
      end

      def fetch
        return yield unless cacheable?

        key = cache_key(@project.repository)
        metadata = read(key)
        cache_hit = valid_metadata?(metadata)
        cache_reads_counter.increment(result: cache_hit ? 'hit' : 'miss')
        return Commit.from_hash(metadata, @project) if cache_hit

        commit = yield
        return commit unless commit

        metadata = {
          id: commit.id, message: commit.message,
          author_name: commit.author_name, author_email: commit.author_email
        }
        write(key, metadata) if valid_metadata?(metadata)

        commit
      end

      private

      def cacheable?
        @sha.is_a?(String) && /\A(?:[0-9a-f]{40}|[0-9a-f]{64})\z/.match?(@sha) &&
          !Gitlab::Database.read_only? && !@project.repository_read_only? && !@project.pending_delete?
      end

      def cache_key(repository)
        "ci:build_hook_commit:v3:{#{@project.id}}:#{repository.shard}:" \
          "#{repository.disk_path}:#{@sha}"
      end

      def valid_metadata?(metadata)
        metadata.is_a?(Hash) && metadata.size == FIELDS.size && metadata[:id] == @sha &&
          FIELDS.all? { |field| metadata[field].is_a?(String) } &&
          metadata.values.sum(&:bytesize) <= MAX_BYTES
      end

      def cache_reads_counter
        @cache_reads_counter ||= Gitlab::Metrics.counter(
          :gitlab_ci_build_hook_commit_cache_reads_total,
          'CI job hook commit cache reads by result'
        )
      end

      def read(key)
        @store.read(key)
      rescue ::Redis::BaseError, ::RedisClient::Error
        nil
      end

      def write(key, value)
        @store.write(key, value, expires_in: TTL)
      rescue ::Redis::BaseError, ::RedisClient::Error
        nil
      end
    end
  end
end
