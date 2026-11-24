# frozen_string_literal: true

module Elastic
  module BulkCronWorker
    extend ActiveSupport::Concern

    RESCHEDULE_INTERVAL = 1.second

    included do
      prepend ::Geo::SkipSecondary
      include ApplicationWorker
      include Search::Worker
      include Gitlab::ExclusiveLeaseHelpers
      # There is no onward scheduling and this cron handles work from across the
      # application, so there's no useful context to add.
      include CronjobQueue # rubocop:disable Scalability/CronWorkerContext
    end

    def perform(shard_number = nil, max_score = nil)
      return false unless Gitlab::CurrentSettings.elasticsearch_indexing?

      return false if ::Gitlab::CurrentSettings.advanced_search_indexing_paused?

      return if legacy_lock_exists? # skip execution if legacy lease is still obtained

      unless Search::ClusterHealthCheck::Elastic.healthy?
        log "advanced search cluster is unhealthy. #{self.class} execution is skipped."
        return false
      end

      if shard_number
        process_shard(shard_number, max_score)
      else
        schedule_shards
      end
    rescue Gitlab::ExclusiveLeaseHelpers::FailedToObtainLockError
      # We're scheduled on a cronjob, so nothing to do here
    end

    private

    def log(message)
      logger.info(structured_payload(message: message))
    end

    def process_shard(shard_number, max_score = nil)
      options = { shards: [shard_number] }
      options[:max_scores] = { shard_number => max_score } if max_score

      in_lock("#{self.class.name.underscore}/shard/#{shard_number}", ttl: 10.minutes, retries: 10, sleep_sec: 1) do
        service.execute(**options).tap do |records_count, failures_count|
          log_extra_metadata_on_done(:records_count, records_count)
          log_extra_metadata_on_done(:shard_number, shard_number)

          # Requeue current worker if the queue isn't empty
          if should_requeue?(records_count: records_count, failures_count: failures_count)
            with_job_args(shard_number) { |args| self.class.perform_in(RESCHEDULE_INTERVAL, *args) }
          end
        end
      end
    end

    def schedule_shards
      Elastic::ProcessBookkeepingService::SHARDS.each do |shard_number|
        with_job_args(shard_number) { |args| self.class.perform_async(*args) }
      end
    end

    def with_job_args(shard_number)
      yield [shard_number]
    end

    def legacy_lock_exists?
      !!Gitlab::ExclusiveLease.get_uuid(self.class.name.underscore)
    end

    def should_requeue?(records_count:, failures_count:)
      return false unless records_count
      return false if failures_count > 0
      return false unless Gitlab::CurrentSettings.elasticsearch_requeue_workers?

      records_count > 0
    end
  end
end
