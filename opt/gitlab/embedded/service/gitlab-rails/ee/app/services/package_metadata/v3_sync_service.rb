# frozen_string_literal: true

module PackageMetadata # rubocop:disable Gitlab/BoundedContexts -- follows existing package_metadata services pattern
  # Shared sync flow for datasets distributed under the v3 contract, whether they
  # arrive over PDS or from a vendor directory. Subclasses name their dataset and
  # supply its ingestion pieces; everything about *how* a run is planned, paced
  # and checkpointed lives here.
  #
  # The split mirrors Connector::Pds and its subclasses: the contract is shared,
  # each dataset contributes only its differences.
  class V3SyncService
    UnknownAdapterError = Class.new(StandardError)

    # Allowlisted so a new dataset does not start emitting an event that has no
    # definition file. Mirrors Connector::Gcp::TRACKED_DATA_TYPES.
    TRACKED_DATA_TYPES = %w[malware_advisories licenses advisories].freeze

    # Every outcome a run can report. One definition file exists per
    # (tracked data type, outcome) pair, so an outcome missing from this list has
    # no event to emit. Each one is documented by the `description` in its
    # ee/config/events/sync_pmdb_v3_<data_type>_<outcome>.yml.
    #
    # delta_backlog is a measurement rather than an outcome (it carries `value`),
    # but it shares the allowlist so every emitted name is checked in one place.
    SYNC_OUTCOMES = %w[
      aborted_no_token
      skipped_stop_signal
      bulk_delta_skipped_stop_signal
      bulk_delta_failed
      skipped_unsupported
      full_completed
      full_interrupted
      full_not_persisted
      full_failed
      delta_completed
      delta_interrupted
      delta_not_persisted
      delta_failed
      delta_up_to_date
      delta_backlog
    ].freeze

    class << self
      include ::Gitlab::InternalEventsTracking

      # Selects the sync configurations, the checkpoint rows and the PDS
      # connector. Must be a String: SyncConfiguration.configs_for and
      # Connector::Pds.class_for both case on string literals, so a Symbol raises.
      def data_type
        raise Gitlab::AbstractMethodError
      end

      def fabricator_class
        raise Gitlab::AbstractMethodError
      end

      def ingestion_service
        raise Gitlab::AbstractMethodError
      end

      # Air-gapped connector, shared by every v3 dataset: the vendor layout it
      # reads belongs to the v3 distribution contract, not to one dataset.
      # PDS-backed runs go through Connector::Pds.for, which dispatches on
      # data_type.
      def offline_connector_class
        Gitlab::PackageMetadata::Connector::OfflineV3
      end

      # Must equal the dataset's worker LEASE_TIMEOUT, with max_sync_duration
      # below it so the run stops before the lease expires.
      def max_lease_length
        raise Gitlab::AbstractMethodError
      end

      def max_sync_duration
        raise Gitlab::AbstractMethodError
      end

      def ingest_slice_size
        raise Gitlab::AbstractMethodError
      end

      def throttle_rate
        raise Gitlab::AbstractMethodError
      end

      # Abstract rather than derived from data_type: log dashboards and searches
      # key on this value, so each subclass states the literal to keep it
      # greppable. dataset_label below only feeds human-readable messages.
      def log_event
        raise Gitlab::AbstractMethodError
      end

      def dataset_label
        data_type.singularize.humanize
      end

      def execute(lease:)
        # Shared by every per-PURL sync in this run so their log lines can be grouped.
        batch_id = SecureRandom.uuid
        signal = PackageMetadata::StopSignal.new(lease, max_lease_length, max_sync_duration)

        configs = SyncConfiguration.configs_for(data_type)
        validate_v3_configs!(configs)

        # Pin the version format: a dataset can hold rows under several, and
        # licenses still carry v2 ones. Loading those into a v3 run would hand it
        # a v2 bookmark, skip the /all bootstrap and advance the wrong row.
        checkpoints = PackageMetadata::Checkpoint
          .for_dataset(data_type, SyncConfiguration::VERSION_FORMAT_V3)
          .index_by(&:purl_type)
        syncs = configs.map do |config|
          { config: config, checkpoint: checkpoints[config.purl_type] || new_checkpoint(config) }
        end

        # Offline syncs don't use the IJWT; only guard PDS-backed runs.
        return if pds_backed?(syncs) && !pds_token_available?(batch_id)

        syncs = filter_to_supported(syncs, batch_id)

        bulk_delta_syncs, individual_syncs = syncs.partition do |sync|
          bulk_delta?(sync[:config], sync[:checkpoint])
        end

        sync_individually(individual_syncs, signal, batch_id)
        sync_bulk_delta(bulk_delta_syncs, signal, batch_id)
      end

      def log(severity, message, **fields)
        payload = { Labkit::Fields::CLASS_NAME => name, message: message, **fields }
        case severity
        when :debug then Gitlab::AppJsonLogger.debug(payload)
        when :warn then Gitlab::AppJsonLogger.warn(payload)
        when :error then Gitlab::AppJsonLogger.error(payload)
        else Gitlab::AppJsonLogger.info(payload)
        end
      end

      # One event name per (data type, outcome) pair, so each outcome is
      # self-describing and queryable without filtering on a property. `label`
      # carries the purl_type; it is omitted for run-wide outcomes that precede
      # any registry, whose definitions declare no label.
      def track_sync_outcome(sync_config, outcome, value: nil)
        unless SYNC_OUTCOMES.include?(outcome)
          # Raises in dev and test, tracked in production: a typo must not take a
          # sync run down over instrumentation.
          Gitlab::ErrorTracking.track_and_raise_for_dev_exception(
            ArgumentError.new("unknown v3 sync outcome: #{outcome}"))
          return
        end

        return unless TRACKED_DATA_TYPES.include?(data_type)

        additional_properties = {}
        additional_properties[:label] = sync_config.purl_type.to_s if sync_config&.purl_type
        additional_properties[:value] = value if value

        track_internal_event("sync_pmdb_v3_#{data_type}_#{outcome}", additional_properties: additional_properties)
      end

      private

      def sync_individually(syncs, signal, batch_id)
        syncs.each do |sync|
          break if stop_before_sync?(signal, batch_id, sync[:config])

          new(sync[:config], signal, batch_id, checkpoint: sync[:checkpoint]).execute
        end
      end

      def sync_bulk_delta(syncs, signal, batch_id)
        return if syncs.empty?

        if signal.stop?
          log(:info, "#{dataset_label} bulk delta skipped: stop signal before bulk fetch",
            event: log_event, phase: 'bulk_delta_skipped',
            batch_id: batch_id, purl_types: syncs.map { |sync| sync[:config].purl_type }, registries: syncs.size)
          Gitlab::InternalEvents.with_batched_redis_writes do
            syncs.each { |sync| track_sync_outcome(sync[:config], 'bulk_delta_skipped_stop_signal') }
          end
          return
        end

        connector = shared_pds_connector(syncs.map { |sync| sync.fetch(:config) }, 'bulk /delta')
        cursors = syncs.to_h { |sync| [sync[:config].purl_type, sync[:checkpoint].sequence] }

        log(:info, "#{dataset_label} bulk delta requested",
          event: log_event, phase: 'bulk_delta_requested',
          batch_id: batch_id, purl_types: cursors.keys, registries: cursors.size)

        begin
          files_by_purl_type = connector.delta_files_for(cursors)
        rescue StandardError => e
          track_bulk_delta_failed(syncs, batch_id, cursors.keys, error_type: e.class.name)
          raise
        end

        # A rejected bulk request answers for nobody, so stop before the loop:
        # running it would hand every registry an empty stream and report the
        # cycle as delta_up_to_date across the board. PDS does not retry a 400,
        # so the run ends here rather than raising.
        if files_by_purl_type.nil?
          track_bulk_delta_failed(syncs, batch_id, cursors.keys)
          return
        end

        track_delta_backlog(syncs, connector.delta_entry_counts)

        syncs.each do |sync|
          break if stop_before_sync?(signal, batch_id, sync[:config])

          files = files_by_purl_type[sync[:config].purl_type] || []
          new(sync[:config], signal, batch_id, checkpoint: sync[:checkpoint]).ingest_prefetched(files)
        end
      end

      # Every registry in the bulk request reports the failure: the request is
      # shared, so none of them synced this cycle. `error_type` is absent when PDS
      # rejected the request outright rather than raising.
      def track_bulk_delta_failed(syncs, batch_id, purl_types, error_type: nil)
        fields = { event: log_event, phase: 'bulk_delta_failed', batch_id: batch_id, purl_types: purl_types }
        fields[Labkit::Fields::ERROR_TYPE] = error_type if error_type
        log(:error, "#{dataset_label} bulk delta failed", **fields)

        Gitlab::InternalEvents.with_batched_redis_writes do
          syncs.each { |sync| track_sync_outcome(sync[:config], 'bulk_delta_failed') }
        end
      end

      # How far behind each registry was when the run started, as the number of
      # delta archives PDS offered. Zero is reported too: it is the signal that an
      # instance is fully caught up, which an outcome event alone cannot express.
      def track_delta_backlog(syncs, counts)
        Gitlab::InternalEvents.with_batched_redis_writes do
          syncs.each do |sync|
            count = counts[sync[:config].purl_type]
            next if count.nil?

            track_sync_outcome(sync[:config], 'delta_backlog', value: count)
          end
        end
      end

      # Both the bulk /delta and /supported calls serve every registry in the run
      # from a single connector, so every config has to name the same endpoint.
      # `call` only names the caller in the error message.
      def shared_pds_connector(configs, call)
        endpoints = configs.map(&:base_uri).uniq
        if endpoints.size > 1
          raise ArgumentError, "#{data_type} #{call} expects one PDS endpoint, got #{endpoints.size}"
        end

        pds_connector(configs.first)
      end

      def pds_connector(config)
        Gitlab::PackageMetadata::Connector::Pds.for(config)
      end

      # Checkpoints load pinned to v3 but are built from config.version_format when
      # missing, so a v2 config would silently create and advance the wrong rows.
      def validate_v3_configs!(configs)
        formats = configs.map(&:version_format).uniq - [SyncConfiguration::VERSION_FORMAT_V3]
        return if formats.empty?

        raise ArgumentError, "#{name} expects v3 sync configurations, got: #{formats.join(', ')}"
      end

      # A registry with no persisted checkpoint yet -- built unsaved, so full_dataset_pending? is
      # true (routes it to /all, not the bulk /delta).
      def new_checkpoint(config)
        PackageMetadata::Checkpoint.new(
          data_type: config.data_type, version_format: config.version_format, purl_type: config.purl_type)
      end

      def pds_backed?(syncs)
        syncs.any? { |sync| sync[:config].storage_type == :pds }
      end

      # The instance JWT is instance-wide and identical for every PDS registry in a
      # run, so check it once up front. Without it every PDS request would go out
      # with an empty bearer and be rejected (401); stop the run and log clearly
      # rather than hammer PDS with unauthenticated calls each cycle.
      def pds_token_available?(batch_id)
        return true if Gitlab::PackageMetadata::Connector::Pds.class_for(data_type).instance_token.present?

        log_sync_aborted(batch_id, 'the instance token (IJWT) is empty')
        track_sync_outcome(nil, 'aborted_no_token')
        false
      rescue StandardError => e
        log_sync_aborted(batch_id, 'could not obtain the instance token (IJWT)', error: e)
        track_sync_outcome(nil, 'aborted_no_token')
        false
      end

      def log_sync_aborted(batch_id, reason, error: nil)
        fields = { event: log_event, phase: 'aborted_no_token', batch_id: batch_id }
        fields[Labkit::Fields::ERROR_TYPE] = error.class.name if error
        log(:error, "#{dataset_label} sync stopped: #{reason}", **fields)
      end

      def filter_to_supported(syncs, batch_id)
        pds_configs = syncs.map { |sync| sync[:config] }.select { |config| config.storage_type == :pds }
        return syncs if pds_configs.empty?

        supported = shared_pds_connector(pds_configs, '/supported').supported_registries
        return syncs if supported.nil?

        supported = supported.to_set
        kept, dropped = syncs.partition do |sync|
          sync[:config].storage_type != :pds ||
            supported.include?(SyncConfiguration.registry_id(sync[:config].purl_type))
        end
        log_unsupported_dropped(dropped, batch_id) if dropped.any?
        kept
      end

      def log_unsupported_dropped(dropped, batch_id)
        log(:info, "#{dataset_label} sync: registries not served by PDS, skipped",
          event: log_event, phase: 'unsupported_skipped', batch_id: batch_id,
          purl_types: dropped.map { |sync| sync[:config].purl_type },
          registries: dropped.map { |sync| SyncConfiguration.registry_id(sync[:config].purl_type) })
        Gitlab::InternalEvents.with_batched_redis_writes do
          dropped.each { |sync| track_sync_outcome(sync[:config], 'skipped_unsupported') }
        end
      end

      def bulk_delta?(config, checkpoint)
        config.storage_type == :pds && !checkpoint.full_dataset_pending?
      end

      # Between-registry guard: when the budget is already spent, skip (and log) the
      # next registry before it is created/run. Distinct from the mid-registry
      # `signal.stop?` in #execute, which stops between a registry's data files.
      def stop_before_sync?(signal, batch_id, config)
        return false unless signal.stop?

        log(:info, "#{dataset_label} sync skipped: stop signal before sync",
          event: log_event, phase: 'skipped',
          batch_id: batch_id, purl_type: config.purl_type,
          data_type: config.data_type, version_format: config.version_format)
        track_sync_outcome(config, 'skipped_stop_signal')
        true
      end
    end

    def initialize(sync_config, signal, batch_id = nil, checkpoint: nil)
      @sync_config = sync_config
      @signal = signal
      @batch_id = batch_id
      @checkpoint = checkpoint
    end

    # Individual path: let the connector fetch this registry's own stream (the /all
    # snapshot on first sync, or a per-registry /delta for offline) and ingest it.
    #
    # A nil stream means PDS rejected the request, so there is nothing to ingest
    # and no outcome to report but the rejection: ingesting it as empty would
    # report a full run as full_completed, or a delta run as delta_up_to_date.
    def execute
      files = connector.data_after(checkpoint)
      return track_fetch_rejected if files.nil?

      ingest_stream(files)
    end

    # Bulk path: ingest the stream the bulk /delta already fetched for this registry.
    def ingest_prefetched(files)
      ingest_stream(files)
    end

    private

    # The connector already logged which request PDS rejected and why. Reported
    # under the mode the run would have taken, so a registry PDS keeps rejecting
    # is visible as repeated failures rather than as a healthy sync.
    def track_fetch_rejected
      mode = checkpoint.full_dataset_pending? ? 'full' : 'delta'

      self.class.log(:error, "#{self.class.dataset_label} sync stopped: PDS rejected the request",
        event: self.class.log_event, phase: 'fetch_rejected', sync_mode: mode, batch_id: batch_id,
        purl_type: sync_config.purl_type, data_type: sync_config.data_type,
        version_format: sync_config.version_format)

      self.class.track_sync_outcome(sync_config, "#{mode}_failed")
    end

    # Shared by both paths: ingest each data file and advance the checkpoint per
    # resumable unit.
    def ingest_stream(files)
      @sync_id = SecureRandom.uuid
      @started_at = Gitlab::Metrics::System.monotonic_time
      @files_ingested = 0
      # Log fields only; the checkpoint advances per file, not per run.
      full_sync = checkpoint.full_dataset_pending?
      # @sync_mode is still the metrics label and what up_to_date? reads: the event names are
      # fixed to full_*/delta_* with no mixed_*, and a run that read nothing still needs one,
      # where observed_sync_mode is nil. The log uses observed_sync_mode.
      @sync_mode = full_sync ? 'full' : 'delta'
      @observed_modes = Set.new
      @from_sequence = checkpoint.sequence
      @from_chunk = checkpoint.chunk
      # A full sync whose marker is already set was started by an earlier run that
      # did not finish; this run resumes it from the shard after from_chunk.
      @resuming = full_sync && checkpoint.full_sync_target_sequence.present?

      log_sync_event('started')

      interrupted = false
      persisted_all = true
      pending_file = nil

      files.each do |file|
        self.class.log(:debug, "Evaluating data for #{sync_config}/#{file}")

        # Commit the previous unit only once this file starts a new one.
        advance_checkpoint(pending_file) if persisted_all && new_unit?(file, pending_file)

        # Stop before the ingest, not after: a unit is only committed on the next
        # file's boundary and an interrupt commits nothing, so a file ingested after
        # this check would be thrown away. Its archive is already fetched either way.
        if signal.stop?
          interrupted = true
          break
        end

        persisted_all = ingest_file(file) && persisted_all
        @files_ingested += 1
        @observed_modes << file_mode(file)
        pending_file = file
      end

      finalize_stream(persisted_all, interrupted, pending_file)

      log_sync_event(interrupted ? 'interrupted' : 'completed')
      track_run_outcome(interrupted, persisted_all)
    rescue StandardError
      # The run still aborts; the event only records that it ended in a failure
      # rather than a clean outcome, which the outcome events alone cannot
      # distinguish from a run that never started. sync_mode is unset only if the
      # checkpoint read itself failed, before the run had a mode.
      self.class.track_sync_outcome(sync_config, "#{sync_mode}_failed") if sync_mode
      raise
    end

    def new_unit?(file, pending_file)
      pending_file.present? && unit_key(file) != unit_key(pending_file)
    end

    # A snapshot resumes shard by shard, a delta archive as a whole. Whether a file
    # is a snapshot is a property of the file, not of the run.
    # https://gitlab.com/gitlab-org/gitlab/-/work_items/628423
    def unit_key(file)
      file.snapshot? ? [file.sequence, file.chunk] : [file.sequence]
    end

    # The marker flags a half-ingested snapshot, keeping full_dataset_pending? true so the next
    # run resumes it. https://gitlab.com/gitlab-org/gitlab/-/work_items/603628
    def advance_checkpoint(file)
      checkpoint.update(sequence: file.sequence, chunk: file.chunk,
        full_sync_target_sequence: file.snapshot? ? file.sequence : nil)
    end

    # The stream ran out, so nothing is half-ingested. An interrupt or a persistence
    # failure commits nothing and resumes from the last complete unit.
    def finalize_stream(persisted_all, interrupted, pending_file)
      return unless persisted_all && !interrupted

      advance_checkpoint(pending_file) if pending_file
      checkpoint.update(full_sync_target_sequence: nil) if checkpoint.full_sync_target_sequence
    end

    def ingest_file(file)
      persisted_all = true
      self.class.fabricator_class.new(data_file: file, sync_config: sync_config)
        .each_slice(self.class.ingest_slice_size) do |data_objects|
          matched, mismatched = partition_by_registry(data_objects)

          # Do not advance this registry's checkpoint from another registry's
          # data; leave it unmoved so the mislabelled archive is re-read, and the
          # registry never silently records a completed sync it did not do.
          persisted_all = false if mismatched.any?

          persisted_all = ingest(matched, file) && persisted_all if matched.any?
          throttle
        end
      persisted_all
    end

    # A run syncs one registry, but a dataset may be able to tell that a record
    # belongs to a different one. Datasets that can, override this to split those
    # records off and log them; by default the whole slice is ingested.
    def partition_by_registry(data_objects)
      [data_objects, []]
    end

    # One structured line per lifecycle transition; (batch_id, sync_id) correlate
    # started/completed/interrupted across distributed logs.
    def log_sync_event(phase)
      fields = {
        event: self.class.log_event,
        phase: phase,
        batch_id: batch_id,
        sync_id: sync_id,
        purl_type: sync_config.purl_type,
        data_type: sync_config.data_type,
        version_format: sync_config.version_format,
        storage_type: sync_config.storage_type.to_s,
        from_sequence: from_sequence,
        from_chunk: from_chunk,
        resuming: resuming
      }

      unless phase == 'started'
        fields[:sync_mode] = observed_sync_mode if observed_sync_mode
        fields[:files_ingested] = files_ingested
        fields[:to_sequence] = checkpoint.sequence
        fields[:to_chunk] = checkpoint.chunk
        fields[:duration_s] = (Gitlab::Metrics::System.monotonic_time - started_at).round(2)
      end

      self.class.log(:info, "#{self.class.dataset_label} sync #{phase}", **fields)
    end

    # Absent until the run has read something. Deriving it from the checkpoint up
    # front is a guess, and it is wrong exactly when a snapshot follows a completed
    # first sync. https://gitlab.com/gitlab-org/gitlab/-/work_items/628423
    def observed_sync_mode
      return 'mixed' if observed_modes.size > 1

      observed_modes.first
    end

    def track_run_outcome(interrupted, persisted_all)
      # A delta run that found nothing to read means the registry is already
      # current. Reported separately so "fully synced" is not indistinguishable
      # from a run that ingested archives. The interrupt has to be excluded: the
      # stop check runs before the ingest, so a run that stops before its first
      # archive also ends with files_ingested == 0 without being current.
      return self.class.track_sync_outcome(sync_config, 'delta_up_to_date') if !interrupted && up_to_date?

      outcome = if interrupted
                  'interrupted'
                elsif persisted_all
                  'completed'
                else
                  'not_persisted'
                end

      self.class.track_sync_outcome(sync_config, "#{sync_mode}_#{outcome}")
    end

    def up_to_date?
      sync_mode == 'delta' && files_ingested == 0
    end

    attr_reader :sync_config, :signal, :batch_id, :sync_id, :sync_mode, :from_sequence, :from_chunk, :resuming,
      :files_ingested, :started_at, :observed_modes

    def ingest(data, _file)
      self.class.ingestion_service.execute(data)
    end

    def file_mode(file)
      file.snapshot? ? 'full' : 'delta'
    end

    def checkpoint
      # v3 datasets share pm_checkpoints, keyed by data_type.
      @checkpoint ||= PackageMetadata::Checkpoint
        .with_path_components(sync_config.data_type, sync_config.version_format, sync_config.purl_type)
    end

    def connector
      @connector ||= case sync_config.storage_type
                     when :pds
                       Gitlab::PackageMetadata::Connector::Pds.for(sync_config)
                     when :offline
                       self.class.offline_connector_class.new(sync_config)
                     else
                       raise UnknownAdapterError, "unable to find '#{sync_config.storage_type}' connector"
                     end
    end

    def throttle
      return if ENV['PM_SYNC_IN_DEV'] == 'true'

      sleep(self.class.throttle_rate)
    end
  end
end
