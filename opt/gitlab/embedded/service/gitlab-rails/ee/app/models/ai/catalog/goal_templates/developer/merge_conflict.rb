# frozen_string_literal: true

module Ai
  module Catalog
    module GoalTemplates
      class Developer
        class MergeConflict
          # "Done" is the diff of the merge request, not the set of conflicted files: a merge commit also carries the
          # other changes of the target branch, so a scope of conflicted files would stop almost every push. The history
          # line overrides the rebase that the system prompt of Duo Developer allows for conflicts.
          TEMPLATE = <<~GOAL.strip
            The merge request %{resource_url} has merge conflicts with its target branch %{target_branch}.
            Resolve them so the merge request can merge again, without changing what it does.

            - Work only on this merge request. Its source branch is %{source_branch} in the project %{source_project_path}. Push there, also when that project is a fork.
            - Understand before you resolve: what the merge request is for, and why %{target_branch} changed the same code. Resolve each conflict so both intents survive.
            - Add to the history of the source branch, and do not rewrite it. Other people and sessions may have pushed to it, and a rebase or force push can drop their work.
            - Done means: GitLab no longer reports a conflict, and the diff of the merge request against %{target_branch} has the same changes as before. Keep every change that %{target_branch} made, also inside the conflicting files. Check this before you push, not after.
            - If a conflict has no resolution that keeps both intents, do not push. Explain the conflict in one note on the merge request.
            - When you are done, post one short note that says how you resolved each conflict.
          GOAL

          def self.template
            TEMPLATE
          end

          def self.vars(resource:, **_)
            {
              resource_url: Gitlab::UrlBuilder.build(resource),
              target_branch: resource.target_branch,
              source_branch: resource.source_branch,
              source_project_path: resource.source_project_path
            }
          end
        end
      end
    end
  end
end
