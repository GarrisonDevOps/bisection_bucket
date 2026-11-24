# frozen_string_literal: true

module Gitlab
  module Ci
    module Pipeline
      module SecurityScanProfiles
        class ScanProfileMappingStore
          REDIS_KEY_PREFIX = 'scan_profile_builds'
          REDIS_TTL = 24.hours.to_i

          def self.redis_key(pipeline_id)
            "#{REDIS_KEY_PREFIX}:#{pipeline_id}"
          end

          def self.profile_id_for_build(build)
            key = redis_key(build.pipeline_id)
            ::Gitlab::Redis::SharedState.with do |redis|
              redis.hget(key, build.name)&.to_i
            end
          end

          def self.persist_mappings(pipeline:, context:)
            return unless context.injected_jobs?

            mappings = {}

            context.each_injected_job_with_profile_id do |job_name, profile_id|
              mappings[job_name] = profile_id.to_s
            end

            return if mappings.empty?

            key = redis_key(pipeline.id)
            ::Gitlab::Redis::SharedState.with do |redis|
              redis.multi do |multi|
                multi.hset(key, mappings)
                multi.expire(key, REDIS_TTL)
              end
            end
          rescue ::Redis::BaseError => e
            ::Gitlab::ErrorTracking.track_exception(e, extra: { pipeline_id: pipeline.id })
          end
        end
      end
    end
  end
end
