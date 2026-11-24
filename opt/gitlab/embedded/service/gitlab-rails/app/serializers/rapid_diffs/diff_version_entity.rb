# frozen_string_literal: true

module RapidDiffs
  class DiffVersionEntity < Grape::Entity
    include Gitlab::Routing
    include MergeRequestsHelper
    include Gitlab::Utils::StrongMemoize

    expose :id

    expose :version_index do |merge_request_diff|
      diff_version_index(merge_request_diff)
    end

    expose :merge_head?, as: :is_merge_head

    expose :latest do |merge_request_diff|
      latest?(merge_request_diff)
    end

    expose :short_commit_sha do |merge_request_diff|
      next unless merge_request_diff.head_commit_sha

      Commit.truncate_sha(merge_request_diff.head_commit_sha)
    end

    expose :commits_count
    expose :created_at

    protected

    def diff_version_index(merge_request_diff)
      options[:version_indexes][merge_request_diff.id]
    end

    def latest_or_merge_head?(merge_request_diff)
      strong_memoize_with(:latest_or_merge_head, merge_request_diff.id) do
        latest?(merge_request_diff) || merge_request_diff.merge_head?
      end
    end

    def latest?(merge_request_diff)
      merge_request_diff.id == merge_request.latest_merge_request_diff_id
    end

    def merge_request
      options[:merge_request]
    end

    def merge_request_diffs
      options[:merge_request_diffs]
    end

    def current_merge_request_diff
      options[:current_merge_request_diff]
    end
  end
end
