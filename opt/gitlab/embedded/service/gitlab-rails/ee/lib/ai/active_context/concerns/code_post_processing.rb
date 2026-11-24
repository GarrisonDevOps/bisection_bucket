# frozen_string_literal: true

module Ai
  module ActiveContext
    module Concerns
      # Shared post-processing logic for semantic code search results.
      module CodePostProcessing
        HIGH_SCORE_THRESHOLD = 0.75
        MEDIUM_SCORE_THRESHOLD = 0.5
        STEEP_DROPOFF_THRESHOLD = 0.15

        # Removes files excluded from Duo context via Ai::FileExclusionService.
        def filter_excluded_results(results, project)
          return results if results.empty?

          file_paths = results.filter_map { |hit| hit['path'] }.uniq
          return results if file_paths.empty?

          exclusion_result = ::Ai::FileExclusionService.new(project).execute(file_paths)
          return results unless exclusion_result.success?

          excluded_paths = exclusion_result.payload.filter_map { |f| f[:path] if f[:excluded] }.to_set
          results.reject { |hit| excluded_paths.include?(hit['path']) }
        end

        # Groups flat hit results by file path, merging adjacent line ranges.
        # Returns groups sorted by descending max score.
        def group_results_by_file(results)
          return [] if results.empty?

          groups_by_path = results.group_by { |hit| hit['path'] }

          groups = groups_by_path.map do |path, hits|
            sorted_hits = hits.sort_by { |hit| hit['start_line'] || 0 }
            merged_ranges = merge_sequential_ranges(sorted_hits)
            first_hit = sorted_hits.first

            {
              path: path,
              project_id: first_hit['project_id'],
              language: first_hit['language'],
              blob_id: first_hit['blob_id'],
              file_url: first_hit['file_url'],
              score: merged_ranges.filter_map { |r| r[:score] }.max,
              snippet_ranges: merged_ranges
            }
          end

          groups.sort_by { |g| -(g[:score] || 0) }
        end

        # Derives a confidence level from the score distribution of results.
        def compute_confidence_level(scores)
          return :unknown if scores.empty?

          top_score = scores.first
          return :low if top_score < MEDIUM_SCORE_THRESHOLD

          if scores.size > 1 && top_score >= HIGH_SCORE_THRESHOLD &&
              top_score - scores[1] >= STEEP_DROPOFF_THRESHOLD
            return :high
          end

          return :high if scores.size <= 1 && top_score >= HIGH_SCORE_THRESHOLD

          :medium
        end

        def extract_scores(results)
          results.filter_map { |hit| hit['score'] }
        end

        private

        def merge_sequential_ranges(sorted_hits)
          return [] if sorted_hits.empty?

          ranges = []
          current_range = nil

          sorted_hits.each do |hit|
            start_line = hit['start_line'] || 0
            end_line = compute_end_line(hit)
            content = hit['content']

            if current_range.nil?
              current_range = build_range(start_line, end_line, content, hit)
            elsif start_line == current_range[:end_line] + 1
              current_range[:end_line] = end_line
              current_range[:content] = "#{current_range[:content]}\n#{content}"
              current_range[:score] = [current_range[:score], hit['score']].compact.max
            else
              ranges << current_range
              current_range = build_range(start_line, end_line, content, hit)
            end
          end

          ranges << current_range
          ranges
        end

        def build_range(start_line, end_line, content, hit)
          { start_line: start_line, end_line: end_line, content: content, score: hit['score'] }
        end

        def compute_end_line(hit)
          start_line = hit['start_line'] || 0
          start_line + (hit['content'] || '').count("\n")
        end
      end
    end
  end
end
