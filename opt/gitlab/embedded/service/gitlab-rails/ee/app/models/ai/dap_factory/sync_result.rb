# frozen_string_literal: true

module Ai
  module DapFactory
    # The outcome of the last Sync for a project, shown by the Factory Editor. Kept in the cache for now:
    # losing it only hides the last outcome until the next push.
    class SyncResult
      CACHE_TTL = 30.days

      SYNCED = 'synced'
      PARTIAL = 'partial'
      INVALID = 'invalid'
      FAILED = 'failed'
      STATUSES = [SYNCED, PARTIAL, INVALID, FAILED].freeze
      DEFAULTS = { 'commit_sha' => nil, 'synced_at' => nil, 'errors' => [], 'summary' => {} }.freeze

      attr_reader :status, :commit_sha, :synced_at, :errors, :summary

      def self.cache_key(project)
        "ai:dap_factory:sync_result:#{project.id}"
      end

      # Only known keys are read, so a result cached before a deploy still loads.
      def self.for(project)
        attributes = Rails.cache.read(cache_key(project))
        return unless attributes.is_a?(Hash) && STATUSES.include?(attributes['status'])

        attributes = DEFAULTS.deep_dup.merge(attributes.slice('status', *DEFAULTS.keys))
        attributes['synced_at'] = Time.zone.parse(attributes['synced_at']) if attributes['synced_at'].is_a?(String)

        new(**attributes.symbolize_keys)
      end

      def initialize(status:, commit_sha:, synced_at:, errors: [], summary: {})
        @status = status
        @commit_sha = commit_sha
        @synced_at = synced_at
        @errors = errors
        @summary = summary
      end

      def save(project)
        Rails.cache.write(self.class.cache_key(project), to_h, expires_in: CACHE_TTL)
        self
      end

      def to_h
        {
          'status' => status,
          'commit_sha' => commit_sha,
          'synced_at' => synced_at&.iso8601,
          'errors' => errors,
          'summary' => summary
        }
      end
    end
  end
end
