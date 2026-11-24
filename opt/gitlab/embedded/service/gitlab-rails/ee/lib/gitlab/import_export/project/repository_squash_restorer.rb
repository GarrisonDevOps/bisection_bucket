# frozen_string_literal: true

module Gitlab
  module ImportExport
    module Project
      # Squashes commit history for custom project template imports.
      #
      # When a project is created from a custom group/instance-level template,
      # this restorer compresses the imported repository history into 2 commits:
      # 1. The original initial commit (first commit with no parents)
      # 2. A squashed commit containing all content, with the initial commit as parent
      #
      # This matches the behavior of built-in project templates (see scripts/vendor_template).
      # A 2-commit approach is used because Gitaly's UserSquash RPC cannot create orphan commits.
      #
      # NOTE: This class is EE-only and is inserted into the restorers list via
      # EE::Gitlab::ImportExport::Importer#post_repo_restorers
      class RepositorySquashRestorer
        SQUASH_COMMIT_MESSAGE = "Initialize from template: %{project_name}"

        def initialize(project:, shared:, user:)
          @project = project
          @shared = shared
          @user = user
        end

        def restore
          return true unless should_squash?

          shared.logger.info(
            message: 'Squashing repository history for custom template import',
            project_id: project.id,
            project_path: project.full_path
          )

          squash_repository_history
          true
        rescue StandardError => e
          shared.error(e)
          false
        end

        private

        attr_reader :project, :shared, :user

        def repository
          @repository ||= project.repository
        end

        def head_commit
          @head_commit ||= repository.commit
        end

        def should_squash?
          return false if ::Feature.disabled?(:squash_history_for_project_templates, project)

          unless repository.exists? && !repository.empty?
            log_skip_reason('repository is empty or does not exist')
            return false
          end

          # Check if HEAD commit has any parents - O(1) vs counting all commits
          # If HEAD has no parents, repo has only 1 commit - nothing to squash
          unless head_commit&.parent_ids&.any?
            log_skip_reason('repository has only one commit')
            return false
          end

          true
        end

        def log_skip_reason(reason)
          shared.logger.info(
            message: "Skipping repository squash: #{reason}",
            project_id: project.id,
            project_path: project.full_path
          )
        end

        def squash_repository_history
          initial_commit = repository.initial_commit

          squash_sha = create_squashed_commit(initial_commit.sha, head_commit.sha)
          update_default_branch(squash_sha)

          repository.expire_all_method_caches
        end

        def create_squashed_commit(start_sha, end_sha)
          repository.squash_commits(
            user,
            start_sha: start_sha,
            end_sha: end_sha,
            message: format(SQUASH_COMMIT_MESSAGE, project_name: project.name)
          )
        end

        def update_default_branch(squash_sha)
          default_branch = repository.root_ref
          # Using write_ref directly since this runs during import with no concurrent access.
          # Higher-level branch update APIs would add unnecessary hook execution overhead.
          repository.write_ref("refs/heads/#{default_branch}", squash_sha)
        end
      end
    end
  end
end
