# frozen_string_literal: true

module RapidDiffs
  class DiffSourceVersionEntity < ::RapidDiffs::DiffVersionEntity
    expose :head_sha do |merge_request_diff| # rubocop:disable Style/SymbolProc -- head_commit_sha takes 0 args; &:head_commit_sha passes options as argument
      merge_request_diff.head_commit_sha
    end

    expose :base_sha do |merge_request_diff| # rubocop:disable Style/SymbolProc -- base_commit_sha takes 0 args; &:base_commit_sha passes options as argument
      merge_request_diff.base_commit_sha
    end

    expose :start_sha do |merge_request_diff| # rubocop:disable Style/SymbolProc -- start_commit_sha takes 0 args; &:start_commit_sha passes options as argument
      merge_request_diff.start_commit_sha
    end

    expose :selected do |merge_request_diff|
      next false if Gitlab::Utils.to_boolean(options[:only_context_commits], default: false)

      if current_merge_request_diff.present?
        next true if current_merge_request_diff.merge_head? && latest_or_merge_head?(merge_request_diff)

        next merge_request_diff.id == current_merge_request_diff.id
      end

      next true if latest_or_merge_head?(merge_request_diff)

      false
    end

    expose :href do |merge_request_diff|
      next compare_path(merge_request_diff) if newer_than_start_version?(merge_request_diff)

      merge_request_version_path(
        merge_request.target_project,
        merge_request,
        merge_request_diff
      )
    end

    private

    # Mirrors DiffResolver: start_sha only applies when it names a version older than this one.
    def newer_than_start_version?(merge_request_diff)
      start_version_id = options[:start_version_id]

      start_version_id.present? && start_version_id < merge_request_diff.id
    end

    def compare_path(merge_request_diff)
      merge_request_version_path(
        merge_request.target_project,
        merge_request,
        merge_request_diff,
        { start_sha: options[:start_sha] }
      )
    end
  end
end
