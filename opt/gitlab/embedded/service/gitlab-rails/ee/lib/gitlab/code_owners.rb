# frozen_string_literal: true

module Gitlab
  module CodeOwners
    FILE_NAME = 'CODEOWNERS'
    FILE_PATHS = [FILE_NAME, "docs/#{FILE_NAME}", ".gitlab/#{FILE_NAME}"].freeze

    def self.for_blob(project, blob)
      if project.feature_available?(:code_owners)
        path = blob.tree? ? "/#{blob.path}/" : blob.path
        Loader.new(project, blob.commit_id, path).members
      else
        []
      end
    end

    # @param project [Project]
    # @param ref [String]
    # Fetch sections from CODEOWNERS file
    def self.sections(project, ref)
      return [] unless project.feature_available?(:code_owners)

      Loader.new(project, ref, []).code_owners_sections
    end

    # @param project [Project]
    # @param ref [String]
    # @param section [String]
    # Checks whether all entries are optional
    def self.optional_section?(project, ref, section)
      return false unless project.feature_available?(:code_owners)

      Loader.new(project, ref, []).optional_section?(section)
    end

    # @param merge_request [MergeRequest]
    # @param merge_request_diff [MergeRequestDiff]
    #   Find code owners entries at a particular MergeRequestDiff.
    #   Assumed to be the most recent one if not provided.
    def self.entries_for_merge_request(merge_request, merge_request_diff: nil)
      project = merge_request.target_project
      return [] unless project.feature_available?(:code_owners) && merge_request.source_project_id

      paths = paths_for_merge_request(merge_request, merge_request_diff)
      Loader.new(project, merge_request.target_branch_ref, paths).entries
    end

    # @param merge_request [MergeRequest]
    # @param sha [String]
    #   Find code owners entries since the specified commit.
    #   Assumed to be the most recent one if not provided.
    def self.entries_since_merge_request_commit(merge_request, sha: nil)
      return [] unless merge_request.project.feature_available?(:code_owners)

      sha ||= merge_request.commit_shas(limit: 2).last
      merge_request_diff = merge_request.merge_request_diff

      paths = if sha == merge_request_diff.head_commit_sha
                # NOTE: The sha could be the same as the head_commit_sha if there is only 1 commit and that got amended.
                paths_for_merge_request(merge_request, merge_request_diff)
              else
                paths_since_commit(merge_request_diff, sha)
              end

      Loader.new(
        merge_request.target_project,
        merge_request.target_branch_ref,
        paths)&.entries || []
    end

    def self.paths_since_commit(current_diff, sha)
      compare = ::MergeRequests::MergeRequestDiffComparison
        .new(current_diff)
        .compare_with(sha)

      return [] unless compare

      compare.changed_paths.flat_map { |cp| [cp.path, cp.old_path] }.compact.uniq
    end
    private_class_method :paths_since_commit

    def self.paths_for_merge_request(merge_request, merge_request_diff)
      # In general merge_head_diff is preferred as we want to include latest changes from the target branch.
      # When there is a merge conflict merge_head_diff may be out of date and could be missing changes related to
      # codeowners.  In that case we fall back to merge_request_diff
      merge_request_diff ||= merge_request.merge_head_diff if merge_request.can_be_merged?
      merge_request_diff ||= merge_request.merge_request_diff

      merge_request_diff.modified_paths(fallback_on_overflow: true)
    end
    private_class_method :paths_for_merge_request
  end
end
