# frozen_string_literal: true

module Gitlab
  module Diff
    class PositionCollection
      include Enumerable
      include Gitlab::Utils::StrongMemoize

      # collection - An array of Gitlab::Diff::Position
      # project - The feature flag actor for unfolding line range starts
      def initialize(collection, diff_head_sha = nil, project: nil)
        @collection = collection
        @diff_head_sha = diff_head_sha
        @project = project
      end

      def each(&block)
        filtered_positions.each(&block)
      end

      def concat(positions)
        tap { @collection.concat(positions) }
      end

      # Doing a lightweight filter in-memory given we're not prepared for querying
      # positions (https://gitlab.com/gitlab-org/gitlab/issues/33271).
      def unfoldable
        select do |position|
          unfoldable?(position) && valid_head_sha?(position)
        end
      end

      private

      def filtered_positions
        @collection.select { |item| item.is_a?(Position) }
      end

      def unfoldable?(position)
        return true if position.unfoldable?
        return false unless unfold_line_range_starts?

        !!position.line_range_start_position&.unfoldable?
      end

      def unfold_line_range_starts?
        Feature.enabled?(:unfold_diff_note_line_range_start, @project)
      end
      strong_memoize_attr :unfold_line_range_starts?

      def valid_head_sha?(position)
        return true unless @diff_head_sha

        position.head_sha == @diff_head_sha
      end
    end
  end
end
