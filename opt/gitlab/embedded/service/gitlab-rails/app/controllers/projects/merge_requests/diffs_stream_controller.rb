# frozen_string_literal: true

module Projects
  module MergeRequests
    class DiffsStreamController < Projects::MergeRequests::ApplicationController
      include RapidDiffs::StreamingResource

      urgency :low, [:diffs_stream]

      before_action :check_diff_resources_rate_limit!, only: [:diffs_stream] # rubocop:disable Rails/LexicallyScopedActionFilter -- diffs_stream is defined in the StreamingResource concern

      private

      def diff_file_component(diff_file)
        ::RapidDiffs::MergeRequestDiffFileComponent.new(
          diff_file: diff_file, merge_request: @merge_request,
          conflict_resolution_path: rapid_diffs_presenter.conflict_resolution_path,
          can_merge: rapid_diffs_presenter.can_merge,
          parallel_view: view == :parallel
        )
      end

      def diff_files_collection(diff_files)
        ::RapidDiffs::MergeRequestDiffFileComponent.with_collection(
          diff_files, merge_request: @merge_request,
          conflict_resolution_path: rapid_diffs_presenter.conflict_resolution_path,
          can_merge: rapid_diffs_presenter.can_merge,
          parallel_view: view == :parallel
        )
      end

      def streaming_diff_options
        rapid_diff_options.merge(only_context_commits: !!rapid_diff_options[:only_context_commits])
      end

      def empty_state_component
        ::RapidDiffs::MergeRequestEmptyStateComponent.new(
          merge_request: @merge_request,
          type: rapid_diffs_presenter.empty_state_type
        )
      end
    end
  end
end
