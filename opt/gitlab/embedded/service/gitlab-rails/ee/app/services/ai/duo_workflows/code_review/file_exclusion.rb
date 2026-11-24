# frozen_string_literal: true

module Ai
  module DuoWorkflows
    module CodeReview
      module FileExclusion
        include ::Gitlab::Utils::StrongMemoize
        include ::Ai::DuoWorkflows::CodeReview::Observability

        FIRST_DIFF_BATCH_SIZE = 10

        private

        def excluded_files
          # Same options as `MergeRequest#ai_reviewable_diff_files`, so the raw diffs memoised on the
          # MergeRequestDiff are reused instead of loading and decorating a second collection.
          excluded_paths(merge_request.diffs(expanded: true).diff_file_paths)
        end
        strong_memoize_attr :excluded_files

        def excluded_paths(file_paths)
          return [] if file_paths.empty?

          result = ::Ai::FileExclusionService.new(merge_request.project).execute(file_paths)
          return [] unless result.success?

          result.payload.filter_map { |file_result| file_result[:path] if file_result[:excluded] }
        end

        # Diff limits and exclusion rules apply file by file in order, so a match in the first batch
        # is also a match in the full collection, and most merge requests never load every patch.
        def ai_reviewable_diff_files?
          first_diff_batch_ai_reviewable? || ai_reviewable_diff_files.any?
        end

        def first_diff_batch_ai_reviewable?
          diff_files = merge_request.merge_request_diff
            .diffs_in_batch(0, FIRST_DIFF_BATCH_SIZE, diff_options: { expanded: true })
            .raw_diff_files
            .select(&:ai_reviewable_patch?)
          return false if diff_files.empty?

          excluded = excluded_paths(diff_files.map(&:file_path)).to_set
          diff_files.any? { |diff_file| excluded.exclude?(diff_file.file_path) }
        end

        def ai_reviewable_diff_files
          excluded = excluded_files.to_set

          merge_request.ai_reviewable_diff_files(patch_only: true).reject do |diff_file|
            excluded.include?(diff_file.file_path)
          end
        end
        strong_memoize_attr :ai_reviewable_diff_files

        def exclusion_message_for_excluded_files
          return "" if excluded_files.empty?

          track_review_merge_request_event('excluded_files_from_duo_code_review')

          context_exclusion_help_path = ::Gitlab::Utils.append_path(
            Gitlab::Routing.url_helpers.root_url,
            Gitlab::Routing.url_helpers.help_page_path('user/gitlab_duo/context.md',
              anchor: 'exclude-context-from-gitlab-duo')
          )

          <<~MESSAGE
               I do not have access to the following files due to an active context exclusion policy:
               #{excluded_files.map { |file| "* #{file}" }.join("\n")}
               [Learn more](#{context_exclusion_help_path})
          MESSAGE
        end
        strong_memoize_attr :exclusion_message_for_excluded_files
      end
    end
  end
end
