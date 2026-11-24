# frozen_string_literal: true

module Gitlab
  module PackageMetadata
    module Connector
      class Offline < BaseConnector
        include Gitlab::Utils::StrongMemoize

        def data_after(checkpoint = nil)
          filepaths = Dir.glob("*/*.#{file_suffix}", base: file_prefix).sort!

          pending_filepaths = pending_files(filepaths, checkpoint)

          fetch_pending_files(pending_filepaths)
        end

        private

        # CVE enrichment is synced without a purl_type, and its export nests the
        # data type a level deeper than a registry-partitioned one:
        # v2/cve_enrichment/<sequence>/<chunk>.ndjson. Read that layout as well
        # as the flattened one operators built while it was unreadable. The
        # resolved prefix is memoized: it is read once per file in
        # fetch_pending_files and again by sequence_and_chunk_from.
        def file_prefix
          base = File.join(sync_config.base_uri, super)
          return base unless sync_config.cve_enrichment?

          nested = File.join(base, sync_config.data_type)
          Dir.exist?(nested) ? nested : base
        end
        strong_memoize_attr :file_prefix

        def file_separator
          File::SEPARATOR
        end

        def pending_files(filepaths, checkpoint)
          # If no checkpoint exists iterate through all filepaths.
          return filepaths if checkpoint.blank?

          # Find index of last checkpointed file.
          checkpoint_index = filepaths.find_index do |filepath|
            sequence, chunk = sequence_and_chunk_from(filepath)

            sequence == checkpoint.sequence && chunk == checkpoint.chunk
          end

          # If the checkpoint was not found, then replay the ingestion to guarantee
          # data consistency.
          return filepaths if checkpoint_index.nil?

          # Drop all filepaths including the last checkpointed file since they've
          # been processed previously by a worker.
          filepaths.drop(checkpoint_index + 1)
        end

        def fetch_pending_files(filepaths)
          filepaths.lazy.map do |filepath|
            path = File.absolute_path(filepath, file_prefix)

            sequence, chunk = sequence_and_chunk_from(filepath)

            data_file_class.new(OfflineFileWrapper.new(path), sequence, chunk)
          end
        end

        class OfflineFileWrapper
          def initialize(path)
            @path = path
          end

          def each_line(&block)
            File.foreach(@path, &block)
          end
        end
      end
    end
  end
end
