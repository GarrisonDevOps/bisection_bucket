# frozen_string_literal: true

module Ai
  module ActiveContext
    module Code
      class IndexerResponseModifier
        SECTION_BREAK = '--section-start--'
        VERSION_HEADER_REGEX = /^version,build_time$/  # Matches: "version,build_time"
        VERSION_DATA_REGEX = /^v[\d.]+-.*,.*UTC$/      # Matches: "v5.6.0-16-gb587744-dev,2025-06-24-0800 UTC"
        ID_SECTION_HEADER = 'id'
        HASH_ID_REGEX = /^[a-f0-9]{64}$/               # Matches: SHA-256 hashes (64 hex chars)

        # Extracts hash IDs from indexer output, skipping section headers and metadata
        #
        # Example output:
        #
        # --section-start--
        # version,build_time
        # v5.6.0-16-gb587744-dev,2025-06-24-0800 UTC
        # --section-start--
        # id
        # hash123
        # hash456

        def initialize(&block)
          @block = block
        end

        def process_line(line)
          line = line.strip
          return if line.empty?
          return if line == SECTION_BREAK              # --section-start--
          return if line.match?(VERSION_HEADER_REGEX)  # version,build_time
          return if line.match?(VERSION_DATA_REGEX)    # v5.6.0-16-gb587744-dev,2025-06-24-0800 UTC
          return if line == ID_SECTION_HEADER          # id
          return unless line.match?(HASH_ID_REGEX)

          block.call(line)
        end

        private

        attr_reader :block
      end
    end
  end
end
