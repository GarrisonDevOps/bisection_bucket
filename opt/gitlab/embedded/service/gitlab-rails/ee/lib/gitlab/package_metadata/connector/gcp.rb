# frozen_string_literal: true

require 'google/apis/storage_v1'
require 'google/cloud/storage'

module Gitlab
  module PackageMetadata
    module Connector
      class Gcp < BaseConnector
        include ::Gitlab::InternalEventsTracking

        MissingChunkFileError = Class.new(StandardError)
        LabelEntry = Struct.new(:timestamp, :chunks, keyword_init: true)
        LABEL_PREFIX = 'v2'
        TRACKED_DATA_TYPES = %w[advisories licenses cve_enrichment].freeze

        def data_after(checkpoint)
          if checkpoint.blank? || checkpoint.sequence.blank?
            track_sync_path('listobjects_blank_checkpoint')
            return all_files
          end

          result = retrieve_data_from_labels(checkpoint)
          return result unless result.nil?

          found_list = all_files.drop_while do |file|
            !file.checkpoint?(checkpoint)
          end

          if found_list.any?
            found_list.drop(1)
          else
            all_files
          end
        end

        private

        # gcp file_prefix has a trailing slash, so the base connector definition
        # is updated to add the trailing slash. CVE enrichment's export nests the
        # data type a level deeper: v2/cve_enrichment/<sequence>/<chunk>.ndjson.
        def file_prefix
          prefix = sync_config.cve_enrichment? ? File.join(super, sync_config.data_type) : super

          File.join(prefix, '')
        end

        def all_files
          bucket.files(prefix: file_prefix).all.lazy.map do |file|
            sequence, chunk = sequence_and_chunk_from(file.name)

            data_file_class.new(GcpFileWrapper.new(file), sequence, chunk)
          end
        end

        def bucket
          connection.bucket(sync_config.base_uri, skip_lookup: true)
        end

        def bucket_with_metadata
          @bucket_with_metadata ||= connection.bucket(sync_config.base_uri)
        end

        def connection
          @connection ||= Google::Cloud::Storage.anonymous
        end

        # Returns label-based data for eligible sync configs (non-CVE),
        # or nil to fall back to listObjects.
        def retrieve_data_from_labels(checkpoint)
          if sync_config.cve_enrichment?
            track_sync_path('listobjects_cve_enrichment')
            return
          end

          data_after_from_labels(checkpoint)
        end

        # Returns an enumerator of files to sync based on bucket labels,
        # or nil to fall back to listObjects.
        def data_after_from_labels(checkpoint)
          entries = label_entries
          if entries.empty?
            log_label_path("no bucket labels found, falling back to listObjects")
            track_sync_path('labels_fallback_no_labels')
            return
          end

          if caught_up?(checkpoint, entries)
            log_label_path("checkpoint caught up via labels, skipping sync")
            track_sync_path('labels_caught_up')
            return []
          end

          if data_missing_from_labels?(checkpoint, entries)
            log_label_path("checkpoint predates label history, falling back to listObjects")
            track_sync_path('labels_fallback_stale_checkpoint')
            return
          end

          log_label_path("fetching files using labels")
          result = files_from_entries(filtered_entries(checkpoint, entries), checkpoint)
          track_sync_path('labels_hit')
          result
        rescue Google::Cloud::Error => e
          Gitlab::ErrorTracking.track_exception(e)
          track_sync_path('labels_fallback_gcs_error')
          nil
        end

        def log_label_path(message)
          Gitlab::AppJsonLogger.debug(
            class: self.class.name,
            message: "package_metadata_sync: #{message}",
            data_type: sync_config.data_type,
            version_format: sync_config.version_format,
            purl_type: sync_config.purl_type
          )
        end

        def track_sync_path(property)
          return unless TRACKED_DATA_TYPES.include?(sync_config.data_type)

          additional_properties = { property: }
          additional_properties[:label] = sync_config.purl_type.to_s if sync_config.purl_type

          track_internal_event(
            "sync_pmdb_v2_#{sync_config.data_type}",
            additional_properties:
          )
        end

        # Not caught up while whole deltas remain ahead of the checkpoint's timestamp.
        # Past the newest known timestamp (label lagging the bucket) counts as caught up.
        # At the newest timestamp, still check chunks read - reaching it isn't finishing it.
        def caught_up?(checkpoint, entries)
          newest = entries.first

          return false if checkpoint.sequence < newest.timestamp
          return true if checkpoint.sequence > newest.timestamp

          first_unread_chunk(newest, checkpoint) >= newest.chunks
        end

        def data_missing_from_labels?(checkpoint, entries)
          checkpoint.sequence > 0 && checkpoint.sequence < entries.last.timestamp
        end

        # The checkpoint's own delta stays in: it may have been read only part-way.
        def filtered_entries(checkpoint, entries)
          entries.select { |e| e.timestamp >= checkpoint.sequence }.reverse
        end

        # The chunk to resume at. Only the delta the checkpoint sits in has
        # chunks behind it; every other delta is unread from its first.
        def first_unread_chunk(entry, checkpoint)
          return 0 unless entry.timestamp == checkpoint.sequence

          # chunks start from 0
          checkpoint.chunk + 1
        end

        # Parses the bucket label for the current registry into an array of
        # LabelEntry structs, sorted newest-first.
        def label_entries
          raw_labels = fetch_registry_labels
          return [] if raw_labels.blank?

          parse_label_string(raw_labels)
        end

        def fetch_registry_labels
          labels = bucket_with_metadata.labels || {}
          labels["#{LABEL_PREFIX}_#{registry_id}"]
        end

        def parse_label_string(value)
          value.split('_').filter_map { |entry| transform_entry(entry) }
            .sort_by { |e| -e.timestamp }
        end

        def transform_entry(entry)
          ts_str, chunks_str = entry.split('-')
          return unless valid_label_entry?(ts_str, chunks_str)

          LabelEntry.new(timestamp: ts_str.to_i, chunks: (chunks_str || 1).to_i)
        end

        # Validates a single label entry matches the format produced by
        # the license-exporter: a positive integer timestamp with an
        # optional positive integer chunk count (e.g. '1675359803' or
        # '1675356202-3').
        def valid_label_entry?(ts_str, chunks_str)
          ts_str&.match?(/\A[1-9]\d*\z/) &&
            (chunks_str.nil? || chunks_str.match?(/\A[1-9]\d*\z/))
        end

        # Builds data file objects by constructing file paths directly,
        # avoiding listObjects.
        def files_from_entries(entries, checkpoint)
          entries.flat_map do |entry|
            (first_unread_chunk(entry, checkpoint)...entry.chunks).filter_map do |i|
              file_path = build_file_path(entry, i)
              file = bucket.file(file_path)
              unless file
                Gitlab::ErrorTracking.track_exception(
                  MissingChunkFileError.new("Missing chunk file in package metadata sync"),
                  file_path: file_path,
                  registry_id: registry_id,
                  timestamp: entry.timestamp,
                  chunk_index: i,
                  expected_chunks: entry.chunks
                )
                next
              end

              build_data_file(file, entry, i)
            end
          end
        end

        def build_file_path(entry, index)
          format("%s%d/%09d.%s", file_prefix, entry.timestamp, index, file_suffix)
        end

        def build_data_file(file, entry, index)
          data_file_class.new(GcpFileWrapper.new(file), entry.timestamp, index)
        end

        # GcpFileWrapper ensures that #download is only called on the gcp file when caller needs to access the data.
        class GcpFileWrapper
          def initialize(gcp_file)
            @gcp_file = gcp_file
          end

          def each_line(&block)
            io.each_line(&block)
          end

          private

          def io
            @io ||= @gcp_file.download(skip_decompress: true)
          end
        end
      end
    end
  end
end
