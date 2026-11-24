# frozen_string_literal: true

# Worker for storing security reports into the database.
#
module Security
  class StoreSecurityReportsByProjectWorker
    include ApplicationWorker
    include SecurityScansQueue

    data_consistency :always
    sidekiq_options retry: 3
    feature_category :vulnerability_management
    worker_resource_boundary :memory

    idempotent!
    # until_executing released the lock when the job started, so two jobs for the same project
    # could execute together and contend on the same (project_id, fingerprint) rows. perform
    # resolves the latest pipeline at run time, so coalescing a duplicate loses nothing.
    deduplicate :until_executed, if_deduplicated: :reschedule_once

    # Bounds how many ingestions can run at once, so they don't all contend on the same
    # heavily-indexed sec tables together (see defer_on_database_health_signal below).
    concurrency_limit -> { 800 }

    # Ordered by index count -- every index is maintained on write, so heavily-indexed tables are
    # the ones whose autovacuum competes with ingestion for WAL bandwidth. This is the intersection
    # of the ingestion write path with the sec tables observed accruing the most dead tuples.
    defer_on_database_health_signal :gitlab_sec, [
      ::Vulnerabilities::Read.table_name,
      ::Vulnerabilities::Finding.table_name,
      ::Vulnerability.table_name,
      ::Vulnerabilities::Identifier.table_name,
      ::Security::FindingEnrichment.table_name,
      ::Vulnerabilities::FindingIdentifier.table_name
    ], 5.minutes

    # The worker frees the slot after ingesting. The expiry only matters if a waiting scan pipeline
    # is never ingested (flag turned off, retries exhausted), so it is not ingested much later.
    AGENTIC_SCAN_SLOT_TTL = 1.day

    # Frees a slot only if it still holds the exact value we read. A newer write, including
    # one for the same pipeline, stays for the rescheduled run.
    RELEASE_SLOT_SCRIPT = <<~LUA
      if redis.call("get", KEYS[1]) == ARGV[1] then
        return redis.call("del", KEYS[1])
      end
      return 0
    LUA

    def self.cache_key(project_id: nil)
      return unless project_id.present?

      "#{name}::latest_pipeline_with_security_reports::#{project_id}"
    end

    # Business logic security scan workload pipelines (Security::AgenticAnalyzer) use their own
    # slot, so they don't displace the regular default-branch pipeline and aren't displaced by it.
    def self.agentic_scan_cache_key(project_id: nil)
      return unless project_id.present?

      "#{name}::latest_agentic_scan_pipeline::#{project_id}"
    end

    def self.store_agentic_scan_pipeline(redis, pipeline)
      redis.set(agentic_scan_cache_key(project_id: pipeline.project_id), slot_value(pipeline),
        ex: AGENTIC_SCAN_SLOT_TTL.to_i)
    end

    # Each write is unique, so freeing a slot cannot delete a later write of the same pipeline
    # (a retried job completes that pipeline again while it is being ingested).
    # Readers take the leading pipeline ID, so values written before this format still work.
    def self.slot_value(pipeline)
      "#{pipeline.id}:#{SecureRandom.hex(4)}"
    end

    def perform(project_id)
      project = Project.find_by_id(project_id)
      return unless project&.can_store_security_reports?

      cache_key = self.class.cache_key(project_id: project.id)
      slot_value = read_slot(cache_key)
      pipeline = find_pipeline(slot_value)
      agentic_enabled = ::Security::AgenticAnalyzer.enabled?(project)

      # Technically possible since this is an async job and pipelines
      # can be deleted between when this job was scheduled and
      # run;very unlikely
      if pipeline
        ingest(pipeline)
        # Scan pipelines also run this job, so free the slot: each regular pipeline is ingested once.
        release_slot(cache_key, slot_value) if agentic_enabled
      end

      # Ingested in the same job, after the regular pipeline, so the until_executed lock still keeps
      # two ingestions for the project apart, and a failing scan cannot block the regular one.
      ingest_agentic_scan_pipeline(project) if agentic_enabled
    end

    private

    def ingest(pipeline)
      ::Security::Ingestion::IngestReportsService.execute(pipeline)
      SecretDetection::GitlabTokenVerificationWorker.perform_async(pipeline.id)
    end

    def ingest_agentic_scan_pipeline(project)
      cache_key = self.class.agentic_scan_cache_key(project_id: project.id)
      slot_value = read_slot(cache_key)
      return if slot_value.blank?

      pipeline = find_pipeline(slot_value)
      ingest(pipeline) if pipeline

      release_slot(cache_key, slot_value)
    end

    # Released against the exact value read, so a write made during ingestion stays.
    def release_slot(cache_key, slot_value)
      Gitlab::Redis::SharedState.with do |redis|
        redis.eval(RELEASE_SLOT_SCRIPT, keys: [cache_key], argv: [slot_value])
      end
    end

    def read_slot(cache_key)
      Gitlab::Redis::SharedState.with { |redis| redis.get(cache_key) }
    end

    def find_pipeline(slot_value)
      # not strictly necessary, but to prevent coercing nil to id 0
      return if slot_value.blank?

      Ci::Pipeline.find_by_id(slot_value.to_i)
    end
  end
end
