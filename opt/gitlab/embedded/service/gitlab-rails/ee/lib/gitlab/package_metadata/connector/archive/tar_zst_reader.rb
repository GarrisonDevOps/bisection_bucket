# frozen_string_literal: true

require 'rubygems/package'
require 'zstd-ruby'

module Gitlab
  module PackageMetadata
    module Connector
      module Archive
        # Reads a .tar.zst archive (zstd-compressed tar) and exposes the NDJSON
        # chunk files inside, plus the `until` epoch from a bundled
        # checkpoint.json when present.
        #
        # A delta archive contains one or more NDJSON chunks named by sequence:
        #
        #   1770301601.tar.zst
        #     |- 00000001.ndjson
        #     `- 00000002.ndjson
        #
        # A full-dataset archive additionally ships a checkpoint.json marking
        # the snapshot cutoff, used as the sync sequence after a full ingest:
        #
        #   full_dataset.tar.zst
        #     |- checkpoint.json        ({"until": 1780656046})
        #     |- 00/000000000.ndjson
        #     `- ff/000000000.ndjson
        #
        # Decompression uses the zstd-ruby gem, which vendors libzstd as C
        # source -- no system zstd binary is needed at runtime.
        class TarZstReader
          DecompressionError = Class.new(StandardError)
          CHECKPOINT_FILENAME = 'checkpoint.json'

          Entry = Struct.new(:name, :io, keyword_init: true) do
            def chunk
              File.basename(name, '.*').to_i
            end

            # The shard (hash bucket) index for a full-dataset entry whose name
            # is "<shard>/<chunk>.ndjson", where <shard> is two hex digits
            # (00..ff). Used by the resumable first sync to checkpoint the last
            # ingested shard (see issue 603628). Parsed base-16 -- "ff" is 255,
            # not the 0 a base-10 String#to_i would give. nil for a flat delta
            # entry that has no shard directory.
            def shard_index
              dir = name[%r{\A([0-9a-f]{2})/}i, 1]
              dir&.to_i(16)
            end
          end

          def initialize(archive_bytes)
            @archive_bytes = archive_bytes
          end

          # Yields Entry instances for each NDJSON file in the archive in the
          # order they appear in the tarball.
          def each_entry
            return to_enum(:each_entry) unless block_given?

            parsed[:entries].each { |entry| yield entry }
          end

          # The `until` epoch from a bundled checkpoint.json, or nil when the
          # archive carries no checkpoint.json (e.g. a delta archive).
          def checkpoint_until
            parsed[:checkpoint_until]
          end

          private

          # Single decompress + tar walk, memoized: collects the NDJSON
          # entries and the checkpoint.json `until` in one pass.
          def parsed
            @parsed ||= begin
              entries = []
              checkpoint_until = nil

              # Full-file decompression into memory. Streaming decompression
              # is tracked in https://gitlab.com/gitlab-org/gitlab/-/work_items/602885
              tar_io = StringIO.new(decompress(@archive_bytes))
              Gem::Package::TarReader.new(tar_io) do |tar|
                tar.each do |tar_entry|
                  next unless tar_entry.file?

                  name = tar_entry.full_name
                  if name.end_with?('.ndjson')
                    entries << Entry.new(name: name, io: StringIO.new(tar_entry.read))
                  elsif File.basename(name) == CHECKPOINT_FILENAME
                    checkpoint_until = parse_until(tar_entry.read)
                  end
                end
              end

              { entries: entries, checkpoint_until: checkpoint_until }
            end
          end

          def parse_until(raw)
            parsed = ::Gitlab::Json::SafeParser.parse(raw)
            parsed['until'] if parsed.is_a?(Hash)
          rescue ::JSON::ParserError
            nil
          end

          def decompress(bytes)
            Zstd.decompress(bytes)
          rescue RuntimeError => e
            # zstd-ruby raises bare RuntimeError from its native extension
            # (e.g. "decompress error error code: <name>"); wrap it so the
            # connector can rescue our typed error consistently.
            raise DecompressionError, "zstd decompression failed: #{e.message}"
          end
        end
      end
    end
  end
end
