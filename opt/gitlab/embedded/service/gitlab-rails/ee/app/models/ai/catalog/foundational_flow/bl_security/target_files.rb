# frozen_string_literal: true

module Ai
  module Catalog
    class FoundationalFlow
      module BlSecurity
        # The files a business logic security scan is restricted to when its goal is a
        # merge request IID and the run checks out a non-default branch: the paths the
        # merge request's latest diff adds or modifies. Deleted files are left out,
        # since nothing is left to scan, and a renamed file counts under its new path.
        #
        # `goal` is the workflow goal: a merge request IID (what GoalTemplates::BlSecurity
        # resolves for a merge request's head pipeline), or a resource URL.
        module TargetFiles
          # Above this many paths the list no longer bounds the scan usefully, so
          # the run falls back to a whole-repository scan.
          MAX_PATHS = 400

          # `paths` is an Array (empty for a deletion-only merge request), or nil
          # when the diff cannot bound the scan. `reason` says why it is nil, and is
          # itself nil when the goal is not a merge request IID at all. `source_branch`
          # is the merge request's source branch, set whenever `paths` is.
          Result = Struct.new(:paths, :reason, :source_branch)

          module_function

          # Memoized per request: the goal validator and the context builder both ask.
          def for_goal(project:, goal:)
            ::Gitlab::SafeRequestStore.fetch([:bl_security_target_files, project.id, goal.to_s]) do
              compute(project, goal)
            end
          end

          def compute(project, goal)
            return Result.new(nil, nil) unless goal.to_s.match?(/\A\d+\z/)

            merge_request = project.merge_requests.find_by_iid(goal)
            return Result.new(nil, :merge_request_not_found) unless merge_request
            # The source branch lives in the fork, not in this project.
            return Result.new(nil, :fork_merge_request) if merge_request.for_fork?

            # Never nil: falls back to an unsaved, empty diff.
            diff = merge_request.merge_request_diff
            return Result.new(nil, :diff_overflow) if diff.overflow?
            return Result.new(nil, :diff_not_collected) unless diff.persisted? && diff.collected?

            rows = diff.merge_request_diff_files.where(deleted_file: false).limit(MAX_PATHS + 1)
              .pluck(:new_path, :old_path)
            return Result.new(nil, :too_many_paths) if rows.size > MAX_PATHS

            # new_path is stored blank when it equals old_path (MergeRequestDiffFile#new_path
            # applies the same fallback), so a plain pluck(:new_path) would drop those files.
            paths = rows.map { |new_path, old_path| new_path.presence || old_path }
            # The engine splits target_files on commas, semicolons and whitespace.
            return Result.new(nil, :unsupported_path) if paths.any? { |path| path.match?(/[\s,;]/) }

            Result.new(paths, nil, merge_request.source_branch)
          end
          private_class_method :compute
        end
      end
    end
  end
end
