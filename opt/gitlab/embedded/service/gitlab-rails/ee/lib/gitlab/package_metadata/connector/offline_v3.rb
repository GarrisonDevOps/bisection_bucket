# frozen_string_literal: true

module Gitlab
  module PackageMetadata
    module Connector
      # Offline connector for v3 datasets, for air-gapped instances. Dataset neutral:
      # the layout belongs to the distribution contract.
      #
      #   <base_uri>/v3/<registry_id>/   # registry id, not purl_type: gem -> rubygem
      #     full_dataset/  checkpoint.json ({"until": <epoch>}) + <hexshard>.tar.zst
      #     deltas/        <unix_seconds>.tar.zst
      #
      # A delta names only the end of its window, so a directory missing one looks
      # like a complete one: continuity is assumed, not checked.
      #
      # Inherits Offline for #file_prefix only.
      class OfflineV3 < Offline
        FULL_DATASET_DIR = 'full_dataset'
        DELTAS_DIR = 'deltas'
        CHECKPOINT_FILENAME = 'checkpoint.json'
        ARCHIVE_SUFFIX = '.tar.zst'
        SNAPSHOT = :snapshot

        def data_after(checkpoint)
          return full_dataset_files(checkpoint) if checkpoint.full_dataset_pending?

          pending_archives(checkpoint.sequence.to_i).lazy.flat_map do |timestamp, source|
            next snapshot_files(timestamp) if source == SNAPSHOT

            files_from(File.join(deltas_dir, source), sequence: timestamp)
          end
        end

        private

        # Everything newer than the checkpoint, oldest first. A tie puts the snapshot
        # first: it is a full replacement, so a delta stamped the same second is a
        # no-op on top of it.
        #
        # TODO: a delta archive is one unit -- an interrupted one is re-read whole.
        # https://gitlab.com/gitlab-org/gitlab/-/work_items/608196
        def pending_archives(since)
          pending = delta_archives.select { |timestamp, _name| timestamp > since }

          snapshot_at = snapshot_until.to_i
          pending << [snapshot_at, SNAPSHOT] if snapshot_at > since

          pending.sort_by { |timestamp, source| [timestamp, source == SNAPSHOT ? 0 : 1] }
        end

        # Read whenever full_dataset_pending? holds: a first sync, or a half-ingested
        # snapshot on an instance that synced long ago. Deltas are ignored: they
        # cannot stand in for a complete dataset.
        def full_dataset_files(checkpoint)
          snapshot_at = snapshot_until
          return [] if snapshot_at.nil?

          resume_after = checkpoint.chunk.to_i if checkpoint.sequence.to_i == snapshot_at
          snapshot_files(snapshot_at, resume_after: resume_after)
        end

        # `resume_after` skips the shards a previous run already ingested.
        def snapshot_files(snapshot_at, resume_after: nil)
          shard_files.lazy.flat_map do |chunk, shard_file|
            next [] if resume_after && chunk <= resume_after

            files_from(File.join(full_dataset_dir, shard_file), sequence: snapshot_at, chunk: chunk,
              snapshot: true)
          end
        end

        # `chunk` is forced for snapshot shards (their base-16 id); a delta archive
        # takes it from each entry's name.
        #
        # `snapshot` marks the shards, which resume one by one; a delta resumes whole.
        #
        # TODO: File.binread holds the whole compressed archive in memory, and
        # TarZstReader decompresses it into memory too. Switch to zstd streaming.
        # https://gitlab.com/gitlab-org/gitlab/-/work_items/602885
        def files_from(path, sequence:, chunk: nil, snapshot: false)
          reader = Connector::Archive::TarZstReader.new(File.binread(path))

          reader.each_entry.map do |entry|
            data_file_class.new(entry.io, sequence, chunk || entry.chunk, snapshot: snapshot)
          end
        end

        # The filename is carried rather than rebuilt from the timestamp: a zero-padded
        # name parses fine but would not rebuild. Names that are not a bare timestamp
        # are dropped rather than coerced, since String#to_i would read one as 0.
        def delta_archives
          Dir.glob("*#{ARCHIVE_SUFFIX}", base: deltas_dir).filter_map do |name|
            stem = name.delete_suffix(ARCHIVE_SUFFIX)
            [stem.to_i, name] if stem.match?(/\A\d+\z/)
          end.sort_by(&:first)
        end

        # Stray names are dropped, not coerced: String#to_i(16) would read their leading hex
        # as a real shard's chunk. Sorted by chunk, not name, to match `resume_after`.
        def shard_files
          Dir.glob("*#{ARCHIVE_SUFFIX}", base: full_dataset_dir).filter_map do |name|
            stem = name.delete_suffix(ARCHIVE_SUFFIX)
            [stem.to_i(16), name] if stem.match?(/\A\h+\z/)
          end.sort_by(&:first)
        end

        # The File.exist? guard lives here because the timeline asks for the snapshot's
        # timestamp on every sync, including where there is no snapshot at all.
        def snapshot_until
          return unless File.exist?(checkpoint_path)

          parsed = ::Gitlab::Json::SafeParser.parse(File.read(checkpoint_path))
          parsed['until'] if parsed.is_a?(Hash)
        rescue JSON::ParserError
          nil
        end

        def deltas_dir
          File.join(file_prefix, DELTAS_DIR)
        end

        def full_dataset_dir
          File.join(file_prefix, FULL_DATASET_DIR)
        end

        def checkpoint_path
          File.join(full_dataset_dir, CHECKPOINT_FILENAME)
        end

        def data_file_class
          ::Gitlab::PackageMetadata::Connector::NdjsonDataFile
        end
      end
    end
  end
end
