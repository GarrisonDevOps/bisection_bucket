# frozen_string_literal: true

module RapidDiffs
  class DiffsStatsEntity < Grape::Entity
    expose :diffs_stats do |diffs_resource, _|
      {
        added_lines: diffs_resource.raw_diff_files.sum(&:added_lines),
        removed_lines: diffs_resource.raw_diff_files.sum(&:removed_lines),
        diffs_count: diffs_resource.raw_diff_files.size,
        real_size: diffs_resource.real_size
      }
    end

    expose :has_encoded_file_paths do |diffs_resource, _|
      encoded_file_paths?(diffs_resource)
    end

    expose :overflow, if: ->(diffs_resource, _) {
      diffs_resource.overflow? || overflow_safe?(diffs_resource.diff_files)
    } do |diffs_resource, options|
      {
        visible_count: visible_count(diffs_resource),
        email_path: options[:email_path],
        diff_path: options[:diff_path]
      }
    end

    private

    def encoded_file_paths?(diffs_resource)
      return true if diffs_resource.raw_diff_files.any? { |diff_file| diff_file.diff.encoded_file_path }

      # Context commit diffs are requested by their stored, already re-encoded paths,
      # so Gitaly never returns the files whose raw paths are not valid UTF-8.
      diffable = diffs_resource.diffable
      diffable.is_a?(::ContextCommitsDiff) && diffable.has_encoded_file_paths?
    end

    def overflow_safe?(diff_collection)
      diff_collection.collapsed_safe_limits? ||
        diff_collection.collapsed_safe_lines? || diff_collection.collapsed_safe_files? ||
        diff_collection.collapsed_safe_bytes?
    end

    def visible_count(diffs_resource)
      # Checks paths, not blobs: every file queues its blobs into one batch,
      # so a single image_diff? call would load the blobs of the whole diff.
      hidden = diffs_resource.raw_diff_files.count do |file|
        file.collapsed? && (file.generated? || !file.image_path?)
      end

      diffs_resource.size - hidden
    end
  end
end
