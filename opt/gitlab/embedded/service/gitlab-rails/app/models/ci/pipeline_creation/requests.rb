# frozen_string_literal: true

# This class represents the metadata for the pipeline creation process up until it succeeds and is persisted or fails
# It has the "in progress" status until it succeeds or fails.
# It stores the data in Redis and it is retained for 5 minutes, or longer while its worker is deferred.
# A ref request is deleted when it finishes.
# The structure of the data is:
# {
#   "REDIS_KEY": {
#     "CREATION_ID": {
#       "error" => "ERROR MESSAGE" <- this field is only present for failed creations
#       "pipeline_id": "PIPELINE_ID" <- this field is only present for successful creations
#       "status": "STATUS"
#       "id": "CREATION_ID"
#       "user_initiated": BOOLEAN <- only present for merge request pipeline creations; a missing
#                                    flag must be treated as user-initiated
#       "started_at": FLOAT <- epoch seconds when the request was recorded; start anchor for the
#                              create_pipeline_from_commit user-experience SLI and the age cutoff
#                              for ref and merge request requests
#       "kept_alive_until": FLOAT <- only present for requests whose worker was deferred; epoch seconds
#                                    until which the request counts as in progress past the age cutoff
#     }
#   }
# }
# NOTE: For general project pipelines, `REDIS_KEY` includes the project ID and the request ID for the pipeline creation.
# This means that the request ID is referenced twice when fetching the request data - in `REDIS_KEY` and in
# `CREATION_ID`. It also means that the value for `REDIS_KEY` will only ever contain one pipeline creation request.
# This is somewhat unexpected, but it is necessary in order to match the data structure for merge request pipelines
# (which can have several pipelines creation requests stored under their `REDIS_KEY`). We've decided that maintaining
# two separate data structures is more confusing and results in more code, so it's better to match the data structures
# even if it means that we have a redundant use of the request ID when storing general project pipeline creation
# requests.
#
# NOTE: The `REDIS_KEY` for general project pipelines MUST contain the request ID (not only the project ID) in order to
# ensure that the keys expire. Some projects are so active that their creation request data will never expire from
# Redis if we store all the pipeline creations for a project under one key.
#
# NOTE: All hash keys should be strings because this data is JSONified for Redis and the pipeline creation workers.
#
# TODO: In an attempt to make the Redis data easier to understand, we plan to simplify the way we store MR pipeline
# creation data in https://gitlab.com/gitlab-org/gitlab/-/issues/509925
module Ci
  module PipelineCreation
    class Requests
      FAILED = 'failed'
      IN_PROGRESS = 'in_progress'
      SUCCEEDED = 'succeeded'
      STATUSES = [FAILED, IN_PROGRESS, SUCCEEDED].freeze

      REDIS_EXPIRATION_TIME = 300
      PROJECT_REDIS_KEY = "pipeline_creation:projects:{%{project_id}}"
      MERGE_REQUEST_REDIS_KEY = "#{PROJECT_REDIS_KEY}:mrs:{%{mr_id}}".freeze
      REQUEST_REDIS_KEY = "#{PROJECT_REDIS_KEY}:request:{%{request_id}}".freeze
      REF_REDIS_KEY = "#{PROJECT_REDIS_KEY}:ref:{%{ref_hash}}".freeze

      class << self
        # A ref request is only read while it is in flight, so a finished one is deleted rather than kept
        # with a final status. Merge request and project requests keep theirs, GraphQL exposes them.
        def failed(request, error)
          return unless request.present?
          return hdel(request) if ref_request?(request)

          hset(request, FAILED, error: error)
        end

        def succeeded(request, pipeline_id)
          return unless request.present?
          return hdel(request) if ref_request?(request)

          hset(request, SUCCEEDED, pipeline_id: pipeline_id)
        end

        def start_for_project(project)
          request_id = generate_id
          request = { 'key' => request_key(project, request_id), 'id' => request_id, 'started_at' => Time.current.to_f }

          hset(request, IN_PROGRESS)

          request
        end

        def start_for_merge_request(merge_request, user_initiated: false)
          request = {
            'key' => merge_request_key(merge_request),
            'id' => generate_id,
            'user_initiated' => user_initiated,
            'started_at' => Time.current.to_f
          }

          hset(request, IN_PROGRESS)

          request
        end

        # A ref request carries its own id rather than a key derived from the ref and SHA. Two pushes of one
        # commit can overlap within the creation window, and finishing a specific id is safe to repeat when
        # Sidekiq delivers a job twice, which a per-SHA counter is not.
        def start_for_ref(project, ref)
          request_id = generate_id
          request = { 'key' => ref_key(project, ref), 'id' => request_id, 'started_at' => Time.current.to_f }

          hset(request, IN_PROGRESS)

          request
        end

        # Keeps an in-progress request for at least `ttl` while its worker is deferred. Never shortens it, so a
        # resume that fails and leaves the job deferred does not cut the deferred deadline short.
        def keep_alive(request, ttl: REDIS_EXPIRATION_TIME)
          return unless request.present? && request['key'].present?

          # Not atomic, but the hooks run before the job is enqueued or performed, so the job cannot write the
          # entry in between.
          entry = hget(request)
          # A finished request means the job already ran, for example when a resume is retried.
          return if entry && entry['status'] != IN_PROGRESS

          now = Time.current.to_f
          ttl = ttl.to_i
          # A deferred job has not run, so a missing entry expired while it waited, and it is restored. Resume
          # restores it for the usual expiry only, as it can be retried after the job ran and finished a ref request.
          entry ||= request.slice('id', 'user_initiated', 'started_at').merge('status' => IN_PROGRESS)
          kept_alive_until = [entry['kept_alive_until'].to_f, now + ttl].max

          Gitlab::Redis::SharedState.with do |redis|
            redis.multi do |transaction|
              transaction.hset(request['key'], request['id'],
                entry.merge('kept_alive_until' => kept_alive_until).to_json)
              extend_expiry(transaction, request['key'], (kept_alive_until - now).ceil)
            end
          end
        end

        def pipeline_creating_for_ref?(project, ref)
          now = Time.current.to_f

          for_ref(project, ref).any? { |request| in_progress?(request, now) }
        end

        def for_ref(project, ref)
          key = ref_key(project, ref)

          Gitlab::Redis::SharedState
            .with { |redis| redis.hvals(key) }
            .filter_map { |request| Gitlab::Json.safe_parse(request) }
        end

        def pipeline_creating_for_merge_request?(merge_request)
          now = Time.current.to_f

          for_merge_request(merge_request).any? { |request| in_progress?(request, now) }
        end

        def for_merge_request(merge_request)
          key = merge_request_key(merge_request)

          Gitlab::Redis::SharedState
            .with { |redis| redis.hvals(key) }
            .filter_map { |request| Gitlab::Json.safe_parse(request) }
        end

        def get_request(project, request_id)
          hget({ 'key' => request_key(project, request_id), 'id' => request_id })
        end

        # Project requests (for example "Run pipeline") are not tied to a ref or merge request head pipeline.
        def project_request?(project, request)
          request.to_h['key'] == request_key(project, request.to_h['id'])
        end

        def ref_request?(request)
          request.to_h['key'].to_s.include?(':ref:{')
        end

        def request_key(project, request_id)
          format(REQUEST_REDIS_KEY, project_id: project.id, request_id: request_id)
        end

        def merge_request_key(merge_request)
          format(MERGE_REQUEST_REDIS_KEY, project_id: merge_request.project_id, mr_id: merge_request.id)
        end

        def ref_key(project, ref)
          ref_hash = Digest::SHA256.hexdigest(ref)
          format(REF_REDIS_KEY, project_id: project.id, ref_hash: ref_hash)
        end

        # Extracts merge request ID from Redis key and returns the MergeRequest object
        #
        # @param key [String] Redis key in MERGE_REQUEST_REDIS_KEY format
        # @return [MergeRequest, nil] The MergeRequest object or nil if not found
        def merge_request_from_key(key)
          return unless key

          match = key.match(/mrs:\{(?<mr_id>\d+)\}/)
          return unless match

          mr_id = match[:mr_id].to_i

          MergeRequest.find(mr_id)
        rescue ActiveRecord::RecordNotFound
          nil
        end

        def hset(request, status, pipeline_id: nil, error: nil)
          Gitlab::Redis::SharedState.with do |redis|
            redis.multi do |transaction|
              transaction.hset(
                request['key'], request['id'],
                {
                  'status' => status,
                  'pipeline_id' => pipeline_id,
                  'error' => error,
                  'id' => request['id'],
                  'user_initiated' => request['user_initiated'],
                  'started_at' => request['started_at']
                }.compact.to_json
              )

              extend_expiry(transaction, request['key'], REDIS_EXPIRATION_TIME)
            end
          end
        end

        # A key can hold requests of several jobs, some kept alive for longer, so a write never shortens it.
        # GT alone would not set a TTL on a new key, as Redis treats no TTL as an infinite one.
        def extend_expiry(transaction, key, ttl)
          transaction.expire(key, ttl, nx: true)
          transaction.expire(key, ttl, gt: true)
        end

        # A key holds the requests of several jobs, and a write never shortens it, so an entry left behind by a
        # lost job would stay while other requests or a deferred one keep the key alive. Age each entry instead.
        def in_progress?(request, now)
          request['status'] == IN_PROGRESS &&
            (request['started_at'].to_f > now - REDIS_EXPIRATION_TIME || request['kept_alive_until'].to_f > now)
        end

        def hget(request)
          Gitlab::Redis::SharedState.with { |redis| Gitlab::Json.safe_parse(redis.hget(request['key'], request['id'])) }
        end

        def hdel(request)
          Gitlab::Redis::SharedState.with { |redis| redis.hdel(request['key'], request['id']) }
        end

        def generate_id
          SecureRandom.uuid
        end
      end
    end
  end
end
