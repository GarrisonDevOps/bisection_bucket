# frozen_string_literal: true

module Gitlab
  module DuoWorkflow
    # Decides how a Duo Agent Platform session gets its repository. By default the runner clones it.
    # When agent-config sets `git_strategy.reference_repository_path`, the job script clones instead and
    # borrows objects from that repository in the image, so only the delta since the image was built is fetched.
    class GitStrategy
      REFERENCE_REPOSITORY_PATH_VARIABLE = 'DUO_WORKFLOW_REFERENCE_REPOSITORY_PATH'
      FETCH_ATTEMPTS = 3

      def initialize(project:, reference_repository_path:)
        @project = project
        @reference_repository_path = reference_repository_path
      end

      # The script clone authenticates through the credential helper, because it runs before origin is rewritten.
      def reference_repository?
        @reference_repository_path.present? &&
          Feature.enabled?(:dap_reference_repository, @project)
      end

      # `empty` gives every session a clean directory before the cache is restored, as the runner clone did.
      def variables
        return {} unless reference_repository?

        {
          GIT_STRATEGY: 'empty',
          GIT_LFS_SKIP_SMUDGE: 1,
          REFERENCE_REPOSITORY_PATH_VARIABLE.to_sym => @reference_repository_path
        }
      end

      def clone_commands
        return [] unless reference_repository?

        [
          'cd "$CI_PROJECT_DIR"',
          'origin_url="${DUO_WORKFLOW_GIT_HTTP_BASE_URL%/}/${GITLAB_PROJECT_PATH}.git"',
          clone_command
        ]
      end

      private

      # A workspace that already has a repository is a resumed suspended session, which keeps its work.
      # Workload jobs get no CI_COMMIT_SHA, so this fetches CI_WORKLOAD_REF, as the runner clone does.
      # The restored cache makes the directory non-empty, so the fallback clones into a subdirectory.
      def clone_command
        reference_path = "$#{REFERENCE_REPOSITORY_PATH_VARIABLE}"

        <<~SH.chomp
          if [ -d .git ]; then
            echo "Keeping the existing repository of the resumed session"
          elif [ -d "#{reference_path}/objects" ]; then
            git init --quiet
            echo "#{reference_path}/objects" >> .git/objects/info/alternates
            git remote add origin "$origin_url"
            #{fetch_workload_ref("-c safe.directory=\"#{reference_path}\"")}
            git checkout --quiet --force FETCH_HEAD
          else
            echo "Reference repository not found at #{reference_path}, cloning without it"
            case "$(git clone -h 2>&1)" in
              *"revision <rev>"*)
                #{clone_workload_ref}
                mv .duo-clone/.git .git
                rmdir .duo-clone
                rm -f .git/objects/bundles/tmp_uri_*
                git checkout --quiet --force HEAD
                ;;
              *)
                git init --quiet
                git remote add origin "$origin_url"
                #{fetch_workload_ref}
                git checkout --quiet --force FETCH_HEAD
                ;;
            esac
          fi
        SH
      end

      def fetch_workload_ref(git_options = nil)
        with_retries(['git', git_options, 'fetch --no-tags --quiet origin "$CI_WORKLOAD_REF"'].compact.join(' '))
      end

      # A failed attempt can leave a partial clone behind, which would make the next attempt fail.
      def clone_workload_ref
        with_retries('rm -rf .duo-clone && git -c transfer.bundleURI=true clone --no-checkout --quiet ' \
          '--revision "$CI_WORKLOAD_REF" -- "$origin_url" .duo-clone')
      end

      # A failing command on the left of `&&` does not trigger the runner's `set -e`, so every attempt runs.
      def with_retries(command)
        "for attempt in $(seq #{FETCH_ATTEMPTS}); do #{command} && break; " \
          "[ \"$attempt\" -lt #{FETCH_ATTEMPTS} ] || exit 1; sleep 5; done"
      end
    end
  end
end
