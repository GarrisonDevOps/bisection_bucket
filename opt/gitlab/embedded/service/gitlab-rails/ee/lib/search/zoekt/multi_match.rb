# frozen_string_literal: true

module Search
  module Zoekt
    class MultiMatch
      include Gitlab::EncodingHelper
      include Search::Zoekt::ResponseParser

      MAX_CHUNKS_PER_FILE = 50
      DEFAULT_REQUESTED_CHUNK_SIZE = 3
      NEW_CHUNK_THRESHOLD = 2
      HIGHLIGHT_START_TAG = 'gitlabzoekt_start_'
      HIGHLIGHT_END_TAG = '_gitlabzoekt_end'
      # LineNumber from zoekt is a 1-based line number
      # https://github.com/sourcegraph/zoekt/blob/91259775f43ca589d8a846e3add881fe59818f82/api.go#L238
      LINE_NUMBER_START = 1

      attr_reader :max_chunks_size

      def initialize(requested_chunk_size = DEFAULT_REQUESTED_CHUNK_SIZE)
        requested_chunk_size ||= DEFAULT_REQUESTED_CHUNK_SIZE
        @max_chunks_size = requested_chunk_size.to_i.clamp(0, MAX_CHUNKS_PER_FILE)
      end

      def blobs_for_project(result, project, ref)
        Search::FoundMultiLineBlob.new(
          path: result[:path],
          chunks: result[:chunks],
          project_path: project.full_path,
          file_url: Gitlab::Routing.url_helpers.project_blob_url(project, File.join(ref, result[:path])),
          blame_url: Gitlab::Routing.url_helpers.project_blame_url(project, File.join(ref, result[:path])),
          match_count_total: result[:match_count_total],
          match_count: result[:match_count],
          project: project,
          language: result[:language]
        )
      end

      def zoekt_extract_result_pages_multi_match(response, per_page, page_limit)
        page = 0
        results = {}
        response.each_file do |file|
          current_page = page / per_page
          break if current_page == page_limit

          results[current_page] ||= []
          next if file[:LineMatches].blank?

          chunks, match_count = chunks_for_each_file_with_limited_match_count(file[:LineMatches])

          project_id = extract_project_id(file)
          results[current_page] << build_result(file, chunks, match_count, project_id)
          page += 1
        end

        results
      end

      private

      def build_result(file, chunks, match_count, project_id)
        {
          path: file[:FileName],
          project_id: project_id,
          chunks: chunks,
          match_count_total: file[:LineMatches].inject(0) { |sum, line| sum + line[:LineFragments].count },
          match_count: match_count,
          language: file[:Language]
        }
      end

      def chunks_for_each_file_with_limited_match_count(linematches)
        chunks = []
        generate_chunk = true # It is set to true at the start to generate the first chunk
        chunk = { lines: {}, match_count_in_chunk: 0 }
        limited_match_count_per_file = 0

        linematches.each.with_index(LINE_NUMBER_START) do |match, line_idx|
          next if match[:FileName]

          if generate_chunk
            chunk = { lines: {}, match_count_in_chunk: 0 }
            generate_context_blobs(match, chunk, :before)
          end

          chunk[:lines][match[:LineNumber]] = {
            text: encode_utf8(Base64.decode64(match[:Line])),
            highlights: highlight_match(match[:LineFragments])
          }
          match_count_per_line = match[:LineFragments].count
          chunk[:match_count_in_chunk] += match_count_per_line
          # Generate lines after the match for the context
          generate_context_blobs(match, chunk, :after)
          generate_chunk = linematches[line_idx].nil? ||
            (linematches[line_idx][:LineNumber] - match[:LineNumber]).abs > NEW_CHUNK_THRESHOLD

          if generate_chunk
            limited_match_count_per_file += chunk[:match_count_in_chunk]
            chunks << transform_chunk(chunk)
          end

          break if chunks.count == max_chunks_size
        end
        [chunks, limited_match_count_per_file]
      end

      def generate_context_blobs(match, chunk, context)
        # There is no before context if first line is match
        return if context == :before && match[:LineNumber] == 1

        decoded_context_array = generate_decoded_context_array(match, context)

        if context == :before
          decoded_context_array.reverse_each.with_index(LINE_NUMBER_START) do |line, line_idx|
            unless chunk[:lines][match[:LineNumber] - line_idx]
              chunk[:lines][match[:LineNumber] - line_idx] = { text: line }
            end
          end
        else
          decoded_context_array.each.with_index(LINE_NUMBER_START) do |line, line_idx|
            unless chunk[:lines][match[:LineNumber] + line_idx]
              chunk[:lines][match[:LineNumber] + line_idx] = { text: line }
            end
          end
        end
      end

      def generate_decoded_context_array(match, context)
        context_encoded_string = context == :before ? match[:Before] : match[:After]
        return [''] if context_encoded_string.blank?

        decoded_string = encode_utf8(Base64.decode64(context_encoded_string))
        return [''] if decoded_string == "\n"

        decoded_string.lines(chomp: true)
      end

      def transform_chunk(chunk)
        {
          match_count_in_chunk: chunk[:match_count_in_chunk],
          lines: chunk[:lines].sort.map do |e|
            { line_number: e[0], text: e[1][:text], highlights: e[1][:highlights] }
          end
        }
      end

      def highlight_match(match_line_fragments)
        match_line_fragments.map do |fragment|
          offset = fragment[:LineOffset]
          [offset, offset + fragment[:MatchLength] - 1]
        end
      end
    end
  end
end
