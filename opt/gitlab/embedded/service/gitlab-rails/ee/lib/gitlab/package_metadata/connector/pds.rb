# frozen_string_literal: true

module Gitlab
  module PackageMetadata
    module Connector
      # Dataset-neutral connector for PDS (PMDB Distribution Service).
      #
      # Everything here belongs to the v3 distribution contract rather than to
      # one dataset: the request shapes, the instance token and identity headers,
      # snapshot and delta selection, per-shard resume, the delta cursor, the
      # registry identifier mapping and the per-registry skip when PDS rejects a
      # request. A subclass supplies only the unit primitive its instance token
      # must carry, the key its endpoints put the archive URL under, and the
      # label its log lines read with; the endpoint comes from
      # sync_config.base_uri.
      #
      # PDS authenticates the instance with an IJWT (Instance JWT) carrying the
      # dataset's scope and returns short-lived signed GCS URLs. The signed URLs
      # are self-authenticating, so the follow-up downloads carry no auth
      # headers. PDS does not name that field the same way on every endpoint, so
      # each subclass declares the key its own endpoints use.
      #
      # Endpoints (relative to sync_config.base_uri, one connector per PURL).
      # `<p>` is the PDS registry id (SyncConfiguration.registry_id, e.g.
      # gem -> rubygem), not the raw purl_type. See
      # https://gitlab.com/gitlab-org/gitlab/-/work_items/607045.
      #   GET {base_uri}/all?purl_type=<p>
      #     First sync. Returns { "until": <epoch>, "shards": [{ "shard": "00",
      #     "signed_url": ... }] } -- one signed URL per shard, each pointing at a
      #     <shard>.tar.zst; every shard shares the snapshot `until`.
      #   GET {base_uri}/delta?since=<p>:<sequence>
      #     Incremental sync (bulk, per-registry). Returns
      #     { "purl_types": { "<p>": [{ "delta": "<ts>", "signed_url": ... }] } };
      #     each delta archive is flat NDJSON chunks. An empty array means the
      #     registry is up to date.
      #
      # Auth needs the full CloudConnector.headers bundle in addition to the IJWT:
      # PDS's auth middleware rejects a bare Authorization header with
      # `401 header mismatch` unless X-Gitlab-Realm (matching the JWT
      # `gitlab_realm` claim) and X-Gitlab-Instance-Id (matching `sub`) are also
      # sent. See https://gitlab.com/gitlab-org/gitlab/-/work_items/602430.
      class Pds < BaseConnector
        ResponseError = Class.new(StandardError)
        UnsupportedDatasetError = Class.new(StandardError)

        # Full-dataset shards and large delta archives can exceed Gitlab::HTTP's
        # ~30s default budget. Align the per-download budget with the service's
        # MAX_SYNC_DURATION (4 minutes); the worker lease (6 minutes) still bounds
        # anything pathological. See
        # https://gitlab.com/gitlab-org/gitlab/-/merge_requests/226660#note_3383990080
        DOWNLOAD_TIMEOUT = 4.minutes

        # Endpoint path segments, relative to sync_config.base_uri.
        FULL_DATASET_PATH = 'all'
        DELTA_PATH = 'delta'
        SUPPORTED_PATH = 'supported'
        SUPPORTED_CACHE_TTL = 12.hours

        class << self
          # The CloudConnector unit primitive this dataset's IJWT must be scoped to.
          def unit_primitive
            raise ::Gitlab::AbstractMethodError
          end

          # The response key this dataset's endpoints put the archive URL under.
          def archive_url_key
            raise ::Gitlab::AbstractMethodError
          end

          # Exposed on the class so a caller can check the instance is entitled to
          # the dataset before building a connector per registry.
          #
          # CloudConnector::Tokens.get returns the right IJWT for both deployments:
          # GitLab.com self-signs per request; SM/Dedicated returns the
          # CustomersDot-issued token.
          def instance_token
            ::CloudConnector::Tokens.get(unit_primitive: unit_primitive, resource: :instance)
          end
        end

        # The connector for the dataset in hand. Callers know they want PDS, not
        # which subclass serves which dataset; each subclass carries its own token
        # scope, and its endpoint arrives on sync_config.
        def self.for(sync_config)
          class_for(sync_config.data_type).new(sync_config)
        end

        # Exposed separately so the token pre-flight, which only needs the token
        # scope, can reach it without building a connector.
        def self.class_for(data_type)
          case data_type
          when 'malware_advisories'
            MalwarePds
          when 'licenses'
            LicensesPds
          when 'advisories'
            AdvisoriesPds
          else
            raise UnsupportedDatasetError, "no PDS connector for data type '#{data_type}'"
          end
        end

        # Returns nil when PDS rejected the request, on the same reasoning as
        # #delta_files_for: an empty stream is how a current registry reads, so a
        # rejection reported that way would look like a clean sync.
        def data_after(checkpoint)
          if checkpoint.full_dataset_pending?
            full_dataset_files(checkpoint)
          else
            delta_files(checkpoint)
          end
        end

        # One bulk /delta for every already-synced registry, returning this run's
        # archives grouped by registry so each checkpoint advances independently.
        #
        #   GET {base_uri}/delta?since=npm:1735689600&since=rubygem:1735689600
        #   200 { "purl_types": { "npm": [{ "delta": "...", "signed_url": "..." }, ...],
        #                         "rubygem": [...] }, "not_supported": ["apk"] }
        #
        # Returns nil when PDS rejected the request, so the caller can tell that
        # apart from an answered request that offered nothing: an empty hash per
        # registry means "caught up", and reporting a rejection that way would
        # make a failed cycle read as a fully synced one.
        def delta_files_for(cursors)
          # Reset before the guards, so a caller never reads the previous call's
          # counts back off an early return.
          @delta_entry_counts = {}

          return {} if cursors.blank?

          # cursors are keyed by purl_type; PDS keys by registry id (gem -> rubygem).
          since = cursors.map do |purl_type, sequence|
            "#{::PackageMetadata::SyncConfiguration.registry_id(purl_type)}:#{sequence}"
          end
          body = fetch(DELTA_PATH, { since: since },
            bulk: true, query_string_normalizer: method(:normalize_since_query))
          return if body.nil?
          return {} if body.blank?

          log_unsupported_registries(body['not_supported']) if body['not_supported'].present?

          missing = missing_registries(cursors.keys, body)
          log_missing_registries(missing) if missing.present?

          cursors.keys.index_with do |purl_type|
            entries = body.dig('purl_types', ::PackageMetadata::SyncConfiguration.registry_id(purl_type))
            # Only count a registry PDS answered for. One it omitted, or listed
            # under not_supported, has no backlog to report, and recording zero
            # would read as "caught up" instead of "not measured".
            @delta_entry_counts[purl_type] = entries.size if entries

            Array.wrap(entries).sort_by { |entry| entry['delta'].to_i }.lazy.flat_map do |entry|
              files_from(entry_url(entry), sequence: entry['delta'].to_i)
            end
          end
        end

        # How many delta archives the last #delta_files_for offered per registry.
        # Read from the response rather than the returned enumerators, which are
        # lazy and would download the archives just to be counted. PDS caps a
        # response at 20 archives per registry, so a registry sitting at the cap
        # is behind by at least that much. A registry PDS did not answer for is
        # absent rather than zero.
        def delta_entry_counts
          @delta_entry_counts || {}
        end

        #   GET {base_uri}/supported -> 200 { "registries": ["npm", "rubygem", "pypi", ...] }
        def supported_registries
          Rails.cache.fetch(supported_registries_cache_key, expires_in: SUPPORTED_CACHE_TTL, skip_nil: true) do
            fetch_supported_registries
          end
        end

        private

        # The dataset's name as it reads in a log line, e.g. 'malware advisories'.
        def dataset_label
          raise ::Gitlab::AbstractMethodError
        end

        # Keyed by the dataset and the PDS endpoint, so neither two datasets nor
        # staging and production (or any future endpoint change) share a cached set.
        def supported_registries_cache_key
          ['package_metadata', self.class.unit_primitive, 'supported_registries', pds_endpoint]
        end

        def fetch_supported_registries
          response = Gitlab::HTTP.get("#{pds_endpoint}/#{SUPPORTED_PATH}", headers: request_headers)

          unless response.success?
            severity = response.code == 404 ? :info : :warn
            log(severity, 'PDS /supported unavailable; syncing all configured registries', status: response.code)
            return
          end

          registries = ::Gitlab::Json::SafeParser.parse(response.body).to_h['registries']
          return registries if registries.is_a?(Array) && registries.any?

          log(:warn, 'PDS /supported returned no usable registry list; syncing all configured registries')
          nil
        rescue StandardError => e
          log(:warn, 'PDS /supported request failed; syncing all configured registries',
            Labkit::Fields::ERROR_TYPE => e.class.name)
          nil
        end

        # Yields one data file per shard of the /all snapshot (each shard archive
        # holds a single NDJSON file; the base-16 shard id is the checkpoint chunk).
        # Resume is driven by the checkpoint:
        #   - fresh sync, or a changed snapshot (a different `until`): fetch every
        #     shard;
        #   - resuming the same snapshot: skip shards already ingested
        #     (chunk <= checkpoint.chunk) so an interrupted run continues where it
        #     stopped.
        # The full_sync_target_sequence marker keeps full_dataset_pending? routing here for
        # the duration of the first sync.
        def full_dataset_files(checkpoint)
          body = fetch(FULL_DATASET_PATH, { purl_type: registry_id })
          return if body.nil?
          return [] if body.blank?

          snapshot_until = body['until']
          resuming = checkpoint.sequence.to_i == snapshot_until
          # Drop malformed entries before sorting so a missing shard id can't
          # crash the sort; each is logged and skipped.
          valid_shards, malformed = Array.wrap(body['shards']).partition { |entry| valid_shard?(entry) }
          malformed.each { |entry| skip_malformed_shard(entry) }

          valid_shards
            .sort_by { |entry| entry['shard'].to_i(16) }
            .lazy.flat_map do |entry|
              shard = entry['shard'].to_i(16)
              next [] if resuming && shard <= checkpoint.chunk.to_i

              files_from(entry_url(entry), sequence: snapshot_until, chunk: shard, snapshot: true)
            end
        end

        # /delta is bulk multi-registry: it accepts one or more repeated
        # `since=<registry_id>:<unix_seconds>` pairs and returns a `purl_types` map
        # keyed by each requested registry. Sync is per-registry (one connector
        # and checkpoint per PURL, like /all), so we send a single pair and read
        # back this registry's array. `checkpoint.sequence` is the last `delta`
        # (or full-dataset `until`) timestamp -- a 10-digit unix-seconds cursor.
        # NB: pass a String, not an Array; Gitlab::HTTP would serialize an array
        # as `since[]=`, which PDS rejects (it reads bare repeated `since=`).
        # A delta's sequence is its `delta` timestamp; its archive is flat NDJSON.
        def delta_files(checkpoint)
          body = fetch(DELTA_PATH, { since: "#{registry_id}:#{checkpoint.sequence}" })
          return if body.nil?
          return [] if body.blank?

          entries = body.dig('purl_types', registry_id) || []
          entries.sort_by { |entry| entry['delta'].to_i }.lazy.flat_map do |entry|
            files_from(entry_url(entry), sequence: entry['delta'].to_i)
          end
        end

        # Downloads a .tar.zst from a signed URL and wraps each NDJSON entry as a
        # data file. `chunk` is forced for full-dataset shards (one file per
        # shard); delta archives fall back to the per-file chunk from the name.
        def files_from(signed_url, sequence:, chunk: nil, snapshot: false)
          reader = Connector::Archive::TarZstReader.new(download(signed_url))
          reader.each_entry.map do |entry|
            data_file_class.new(entry.io, sequence, chunk || entry.chunk, snapshot: snapshot)
          end
        end

        # A shard entry must carry both its id and an archive URL to be usable.
        def valid_shard?(entry)
          entry['shard'].present? && entry_url(entry).present?
        end

        def entry_url(entry)
          entry[self.class.archive_url_key]
        end

        # A malformed entry (missing shard id or signed URL) would otherwise raise
        # a cryptic NoMethodError mid-stream. Log it and skip it so one bad entry
        # degrades to a single missing shard (observable in logs) rather than
        # failing the whole sync.
        def skip_malformed_shard(entry)
          log(:error, 'Skipping malformed PDS shard entry',
            purl_type: sync_config.purl_type, shard: entry['shard'])
          []
        end

        def fetch(path, query, bulk: false, **options)
          response = Gitlab::HTTP.get("#{pds_endpoint}/#{path}", query: query, headers: request_headers, **options)

          # 204 is the normal "no new data" answer (registry already up to date);
          # log it so the no-op path is observable rather than silent. Empty hash
          # rather than nil: PDS answered, it just had nothing to hand over.
          if response.code == 204
            log_event("PDS reports no new #{dataset_label}", path: path, status: 204)
            return {}
          end

          # A 400 won't succeed on retry, so log and skip rather than raising. Per
          # registry it means PDS does not serve this dataset for that purl_type; on the
          # bulk request it means the whole /delta was rejected -- log that distinctly so
          # a bulk failure is not mistaken for "no updates for any registry".
          #
          # nil, unlike the 204 above, so a caller that needs to separate "no
          # answer" from "nothing new" can. Callers that treat both as empty read
          # this through `blank?` and are unaffected.
          if response.code == 400
            bulk ? log_bulk_request_rejected(response) : log_skipped_purl_type(response)
            return
          end

          unless response.success?
            log_failure("Failed to fetch #{dataset_label} from PDS", response.code)
            raise ResponseError, "Failed to fetch from PDS: #{response.code}"
          end

          log_event("Fetched #{dataset_label} from PDS", path: path, status: response.code)
          # Parse the body explicitly instead of relying on parsed_response, which
          # only parses when the response carries a JSON content-type header.
          # SafeParser bounds the size/complexity of the external PDS response.
          ::Gitlab::Json::SafeParser.parse(response.body)
        end

        # TODO: buffers the entire compressed archive in memory (response.body)
        # before TarZstReader decompresses it, also fully, into memory. Switch to
        # zstd streaming -- stream the response body through the reader -- so a
        # large shard is not held resident twice.
        # https://gitlab.com/gitlab-org/gitlab/-/work_items/602885
        def download(signed_url)
          response = Gitlab::HTTP.get(signed_url, timeout: DOWNLOAD_TIMEOUT)
          return response.body if response.success?

          log_failure("Failed to download #{dataset_label} archive from signed URL", response.code)
          raise ResponseError, "Failed to download archive: #{response.code}"
        end

        # PDS requires the CloudConnector identity headers (X-Gitlab-Realm,
        # X-Gitlab-Instance-Id, ...) alongside the IJWT. Sync is instance-scoped,
        # so there is no user.
        def request_headers
          ::CloudConnector.headers(nil).merge('Authorization' => "Bearer #{ijwt_token}")
        end

        # Injects the class name and routes to the level, so every log_* helper is a
        # one-liner and Gitlab::AppJsonLogger lives in one place.
        def log(severity, message, **fields)
          payload = { Labkit::Fields::CLASS_NAME => self.class.name, message: message, **fields }
          case severity
          when :debug then Gitlab::AppJsonLogger.debug(payload)
          when :warn then Gitlab::AppJsonLogger.warn(payload)
          when :error then Gitlab::AppJsonLogger.error(payload)
          else Gitlab::AppJsonLogger.info(payload)
          end
        end

        def log_failure(message, status)
          log(:error, message, purl_type: sync_config.purl_type, status: status)
        end

        def log_event(message, **details)
          log(:info, message, purl_type: sync_config.purl_type, **details)
        end

        def log_unsupported_registries(registries)
          log(:info, 'PDS reported unsupported registries in bulk delta',
            not_supported: Array.wrap(registries))
        end

        def normalize_since_query(query)
          Array(query[:since] || query['since']).map { |pair| "since=#{CGI.escape(pair.to_s)}" }.join('&')
        end

        def missing_registries(purl_types, body)
          returned = Array(body['purl_types']&.keys) + Array.wrap(body['not_supported'])
          purl_types.reject do |purl_type|
            returned.include?(::PackageMetadata::SyncConfiguration.registry_id(purl_type))
          end
        end

        def log_missing_registries(purl_types)
          log(:warn, 'PDS omitted requested registries from bulk delta', missing: purl_types)
        end

        # Logs the PDS-rejected purl_type (with the response reason) so a skipped
        # registry is observable, then the fetch returns nil and the sync moves on.
        def log_skipped_purl_type(response)
          log(:warn, 'Skipping purl_type: PDS rejected the request',
            purl_type: sync_config.purl_type, status: response.code,
            reason: response.body.to_s[0, 300])
        end

        # A rejected bulk /delta is a whole-request failure, not a per-registry skip:
        # log it at error so it is not silently read as "no updates for any registry".
        def log_bulk_request_rejected(response)
          log(:error, 'Bulk /delta rejected by PDS; no registries synced this cycle',
            status: response.code, reason: response.body.to_s[0, 300])
        end

        def pds_endpoint
          sync_config.base_uri
        end

        def ijwt_token
          @ijwt_token ||= self.class.instance_token
        end
      end
    end
  end
end
