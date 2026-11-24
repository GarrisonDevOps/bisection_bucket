# frozen_string_literal: true

module Ai
  module DuoWorkflows
    class StartWorkflowService
      include Gitlab::Utils::StrongMemoize

      GITLAB_IMAGE_REGISTRY = 'registry.gitlab.com'
      # When updating this image version, ensure the Duo CLI e2e test image stays in sync:
      # https://gitlab.com/gitlab-org/editor-extensions/gitlab-lsp/-/blob/main/packages/cli/test/production-headless-e2e/docker/Dockerfile#L3
      IMAGE_PATH = "gitlab-org/duo-workflow/default-docker-image/workflow-generic-image:v0.1.1"
      DUO_CLI_VERSION = "10.3.0"
      DUO_WORKFLOW_SERVICE_TOKEN_PLACEHOLDER = 'unused'
      DUO_CLI_PROJECT_ID = "46519181"
      DUO_CLI_INSTALL_DIR = "/usr/local/bin"
      DUO_CLI_REGISTRY_BASE_URL = "https://gitlab.com/api/v4/projects"
      # EX_TEMPFAIL. duo-cli exits with this when the session stops for human input.
      SUSPEND_ON_INPUT_EXIT_CODE = 75
      # /tmp is within the sandbox allowWrite list, so this directory is writable by the agent.
      GIT_HOOKS_DIR = "/tmp/git-hooks"
      # Identifies our own commit-msg hook, so reinstalling over a resumed environment
      # does not chain the hook into itself. Written into the hook body verbatim.
      GIT_HOOK_MARKER = "# installed-by: gitlab-duo-agent-platform"
      # Scheme, host and any non-default port, no path. Used for the helper's own
      # stdin check: git sends the host (not the path) in the credential request, so
      # the check must match on protocol+host only.
      def self.gitlab_origin
        uri = URI.parse(Gitlab.config.gitlab.url)
        origin = "#{uri.scheme}://#{uri.host}"
        origin += ":#{uri.port}" unless uri.port == uri.default_port

        origin
      end

      # Reads the token at invocation time, so it never lands in a URL or .git/config.
      #
      # The credential.<url>.helper key this is installed under is the real access
      # control; these checks are defence in depth. Were the instance URL ever blank the
      # key becomes credential..helper, which git treats as unscoped and offers to every
      # host. Protocol is checked with host so the same case cannot be downgraded to
      # http. Git sends the request on stdin, and it is matched per whole line because a
      # glob over the raw request would answer a host merely containing our own.
      #
      # An absent token prints nothing: git ignores a helper's exit status and accepts a
      # bare `password=` as an empty password, so declining to print is what stops it
      # sending oauth: with no secret and failing auth on every operation.
      def self.git_credential_helper
        '!f() { [ "$1" = get ] || exit 0; p=; h=; while IFS= read -r l; do ' \
          'case "$l" in protocol=*) p="${l#protocol=}";; host=*) h="${l#host=}";; esac; done; ' \
          "[ \"$p://$h\" = \"#{gitlab_origin}\" ] || exit 0; " \
          '[ -n "${GIT_PASSWORD}" ] || exit 1; ' \
          'echo "username=oauth"; echo "password=${GIT_PASSWORD}"; }; f'
      end

      def initialize(workflow:, params:)
        @workflow = workflow
        @current_user = workflow.user
        @service_account = params[:service_account]
        @params = params
      end

      def execute
        unless @workflow.project_level?
          return ServiceResponse.error(
            message: 'Only project-level workflow is supported',
            reason: :unprocessable_entity)
        end

        unless Ability.allowed?(@current_user, :execute_duo_workflow_in_ci, @workflow)
          return ServiceResponse.error(message: 'Can not execute workflow in CI',
            reason: :feature_unavailable)
        end

        if duo_config.config_present? && !duo_config.valid_format?
          config_file = ::Gitlab::DuoAgentPlatform::Config::CONFIG_FILE_NAME
          errors = duo_config.validation_errors.join('; ').first(2000)
          return ServiceResponse.error(
            message: "Invalid config file #{config_file} -> #{errors}",
            reason: :unprocessable_entity)
        end

        unless service_account.present?
          return ServiceResponse.error(
            message: 'Service account is required but was not provided.',
            reason: :invalid_service_account)
        end

        link_composite_identity

        branch_response = create_workload_branch
        unless branch_response.success?
          return ServiceResponse.error(message: branch_response.message, reason: branch_response.reason)
        end

        @ref = branch_response.payload[:ref]

        run_workload
      end

      private

      attr_reader :service_account

      # Derives the legacy DUO_WORKFLOW_DEFINITION env var from the explicit
      # routing components. Older CLI versions use this for flow routing;
      # newer ones use FLOW_CONFIG_ID + FLOW_CONFIG_SCHEMA_VERSION directly.
      #
      # Custom (non-foundational) flows have no flow_config_id; fall back to
      # the stable identity on the workflow record (e.g. 'ai_catalog_agent').
      def resolved_workflow_definition
        return @workflow.workflow_definition if @params[:flow_config_id].blank?

        "#{@params[:flow_config_id]}/#{@params[:flow_config_schema_version]}"
      end

      def run_workload
        service = ::Ci::Workloads::RunWorkloadService.new(
          project: project,
          current_user: service_account,
          source: :duo_workflow,
          workload_definition: workload_definition,
          ref: @ref,
          # `duo_workflow_definition:` uses the stable identity (@workflow.workflow_definition,
          # e.g. "developer/v1") - NOT the resolved routing value. This string is the key for:
          #   - Pipeline rate-limit exclusions (Gitlab::Ci::Pipeline::Chain::Limit::RateLimit)
          #   - Credits/billing (Ai::UsageQuotaService -> CustomersDot feature_qualified_name)
          #   - Analytics (`duo_workflow_workload_completed` event property)
          # Changing it on a feature-flag route-switch would silently affect all three.
          # Routing-derived value is used for DUO_WORKFLOW_DEFINITION env var below.
          duo_workflow_definition: @workflow.workflow_definition
        )
        response = Gitlab::ApplicationContext.with_context(duo_workflow_id: @workflow.id.to_s) { service.execute }

        if response.success?
          workload = response.payload
          workflow_workload = @workflow.workflows_workloads.create(project_id: project.id, workload_id: workload.id)
          unless workflow_workload.persisted?
            return ServiceResponse.error(
              message: workflow_workload.errors.full_messages.join(', '),
              reason: :workflow_workload_failure
            )
          end

          ServiceResponse.success(payload: { workload_id: workload.id })
        else
          ServiceResponse.error(message: response.message, reason: :workload_failure)
        end
      end

      def workload_definition
        ::Ci::Workloads::WorkloadDefinition.new do |d|
          d.image = workload_image
          d.variables = variables
          d.id_tokens = duo_config.id_tokens
          d.commands = commands
          # Caches serve the setup script; skip when there is no coding environment to set up.
          d.cache = cache_configuration if cache_configuration.present? && !skip_coding_environment?
          d.tags = [workload_tag]
          # Forward report_artifacts from the foundational flow definition so the
          # CI job declares artifact reports (e.g. SAST).
          reports = @params[:report_artifacts]

          if reports.present? && !reports.is_a?(Hash)
            Gitlab::AppJsonLogger.warn(
              message: 'report_artifacts is not a Hash, ignoring',
              report_artifacts_class: reports.class.name,
              foundational_flow_reference: @params[:flow_config_id],
              workflow_id: @workflow&.id,
              project_id: @workflow&.project_id
            )
          end

          if reports.is_a?(Hash) && reports.present?
            d.artifacts_reports = reports
            # Reports feed the Vulnerability Report, so store them for its audience (Developer and above).
            d.artifacts_access = 'developer'
          end

          d.suspend_on_success = dap_suspend_env? && !dynamic_suspension?
          d.suspend_on_failure = dap_suspend_env?
          d.allow_failure_exit_codes = [SUSPEND_ON_INPUT_EXIT_CODE] if dynamic_suspension?
          d.runtime_environment_key = ci_runtime_environment_key if dap_suspend_env?
        end
      end

      def workload_tag
        ::Ai::DuoWorkflows::Workflow.workload_tag_for(project)
      end
      strong_memoize_attr :workload_tag

      # Only the suspendable fleet can suspend; resuming elsewhere would pin to an unreachable runner.
      def dap_suspend_env?
        workload_tag == ::Ai::DuoWorkflows::Workflow::SUSPENDABLE_WORKLOAD_TAG &&
          Feature.enabled?(:suspendable_environment_for_dap, project)
      end
      strong_memoize_attr :dap_suspend_env?

      # Keep the environment only when duo-cli stops for human input. The job fails with
      # SUSPEND_ON_INPUT_EXIT_CODE, which the runner suspends on and allow_failure hides.
      def dynamic_suspension?
        dap_suspend_env? && Feature.enabled?(:dap_dynamic_suspension, project)
      end
      strong_memoize_attr :dynamic_suspension?

      def dynamic_suspension_variables
        return {} unless dynamic_suspension?

        { DUO_SUSPEND_ON_INPUT_EXIT_CODE: SUSPEND_ON_INPUT_EXIT_CODE.to_s }
      end

      def ci_runtime_environment_key
        nil # overridden in ResumeWorkflowService
      end

      def workload_image
        return gitlab_image if gitlab_hosted_runner_only?

        @workflow.image.presence || configured_image || instance_image
      end

      def configured_image
        return unless project

        duo_config.default_image
      end

      # Ignores the admin-settable registry, so a GitLab-hosted-runner-only flow always runs GitLab's image.
      def gitlab_image
        "#{GITLAB_IMAGE_REGISTRY}/#{IMAGE_PATH}"
      end

      def instance_image
        host = ci_template_registry_host

        # A trailing slash marks a registry path prefix, such as a Harbor proxy project.
        # Without it, a path can't be told apart from an untagged full image reference.
        return "#{host}#{IMAGE_PATH}" if host.end_with?('/')

        # Return the host if it appears to be a full path to an image rather than
        # just a registry domain:
        return host if host.include?('/')

        "#{host}/#{IMAGE_PATH}"
      end

      def ci_template_registry_host
        Gitlab::CurrentSettings.duo_workflows_default_image_registry.presence || GITLAB_IMAGE_REGISTRY
      end

      def sandbox
        @sandbox ||= ::Gitlab::DuoWorkflow::Sandbox.new(
          current_user: @current_user,
          duo_workflow_service_url: duo_workflow_service_url,
          duo_config: duo_config,
          project: project,
          unmask_env_variables: unmask_env_variables
        )
      end

      def duo_config
        @duo_config ||= ::Gitlab::DuoAgentPlatform::Config.new(project)
      end

      def git_strategy
        @git_strategy ||= ::Gitlab::DuoWorkflow::GitStrategy.new(
          project: project,
          reference_repository_path: (duo_config.reference_repository_path unless gitlab_hosted_runner_only?)
        )
      end

      def cache_configuration
        return unless project
        return if gitlab_hosted_runner_only?

        duo_config.cache_config
      end

      def id_tokens
        return {} unless project

        duo_config.id_tokens || {}
      end

      # A list of environment variables which should not be stripped from the
      # running agent execution environment.
      def unmask_env_variables
        base_variables.merge(git_environment_variables)
          .merge(token_variables)
          .merge(id_tokens)
          .keys
      end

      def setup_script_commands
        return [] unless project
        return [] if gitlab_hosted_runner_only?

        duo_config.setup_script || []
      end

      # Installs a commit-msg git hook that appends Duo session trailers to every
      # commit. The hook is placed in GIT_HOOKS_DIR (/tmp/git-hooks), which is
      # within the sandbox allowWrite list. core.hooksPath is set via GIT_CONFIG_*
      # environment variables so all git invocations pick it up automatically,
      # regardless of whether they use run_git_command or run_command.
      #
      # The hook is only installed when session tracking is enabled for the project.
      def git_hooks_setup_commands
        return [] unless project.project_setting.dap_session_tracking_enabled?

        duo_session_url = @workflow.web_url

        # --if-exists addIfDifferent makes the operation idempotent: trailers are
        # only appended when not already present, so re-runs and amends are safe.
        hook_lines = [
          "#!/bin/sh",
          GIT_HOOK_MARKER,
          # Run the pre-existing (framework) commit-msg hook first, if we saved one.
          # Preserve its ability to reject the commit by propagating a non-zero exit.
          %(if [ -x "#{GIT_HOOKS_DIR}/commit-msg.orig" ]; then "#{GIT_HOOKS_DIR}/commit-msg.orig" "$1" || exit $?; fi),
          "git interpret-trailers \\",
          "  --if-exists addIfDifferent \\",
          "  --trailer #{Shellwords.escape('Co-authored-by: GitLab Duo <duo@gitlab.com>')} \\",
          "  --trailer #{Shellwords.escape("Duo-Session: #{duo_session_url}")} \\",
          "  --in-place \"$1\""
        ]

        hook_content = Shellwords.escape(hook_lines.join("\n"))

        [
          %(mkdir -p #{GIT_HOOKS_DIR}),
          # If a commit-msg hook already exists (e.g. installed by lefthook during
          # setup_script), preserve it as commit-msg.orig so our hook can chain to it.
          # A resumed workload reuses the filesystem, so the existing hook may be one
          # we wrote: moving that to commit-msg.orig would make it invoke itself, and
          # would overwrite the framework hook preserved by the first install.
          %(if [ -f #{GIT_HOOKS_DIR}/commit-msg ] && ) +
            %(! grep -qF #{Shellwords.escape(GIT_HOOK_MARKER)} #{GIT_HOOKS_DIR}/commit-msg; then ) +
            %(mv #{GIT_HOOKS_DIR}/commit-msg #{GIT_HOOKS_DIR}/commit-msg.orig; fi),
          %(printf %s #{hook_content} > #{GIT_HOOKS_DIR}/commit-msg),
          %(chmod +x #{GIT_HOOKS_DIR}/commit-msg)
        ]
      end

      def coding_environment
        @coding_environment ||= ::Ai::Catalog::CodingEnvironment.resolve(
          workflow_definition: @workflow.workflow_definition,
          flow_config: @params[:flow_config],
          user: @workflow.user
        )
      end

      def skip_coding_environment?
        coding_environment == :none
      end

      # A gitlab_hosted_runner_only flow runs only GitLab-controlled code: GitLab's image and
      # `duo` binary, nothing the project configures.
      def gitlab_hosted_runner_only?
        !!@workflow.foundational_flow&.gitlab_hosted_runner_only
      end

      def git_clone_variables
        return { GIT_STRATEGY: 'none' } if skip_coding_environment?
        return git_strategy.variables if git_strategy.reference_repository?

        { GIT_DEPTH: 0, GIT_LFS_SKIP_SMUDGE: 1 }
          .merge(unfiltered_clone? ? native_clone_variables : blobless_fetch_variables)
          .merge(git_source_retry_variables)
      end

      def git_source_retry_variables
        return {} if skip_coding_environment?

        { GET_SOURCES_ATTEMPTS: 6 }
      end

      # Native `git clone` bootstraps from the Gitaly bundle URI, so only the delta
      # is fetched from Gitaly. GIT_FETCH_EXTRA_FLAGS is ignored on this path.
      def native_clone_variables
        {
          GIT_STRATEGY: 'clone',
          FF_USE_GIT_NATIVE_CLONE: 'true',
          GIT_CLONE_EXTRA_FLAGS: '--quiet'
        }
      end

      # GIT_FETCH_EXTRA_FLAGS replaces the runner's default `--prune --quiet`, so both
      # are restored: --quiet keeps ~28k per-ref lines out of the 4 MB job log and
      # --prune drops stale origin/* refs in reused build directories.
      def blobless_fetch_variables
        { GIT_FETCH_EXTRA_FLAGS: '--prune --quiet --filter=blob:none' }
      end

      def unfiltered_clone?
        Feature.enabled?(:dap_unfiltered_clone, project)
      end

      def blob_none_filter
        '--filter=blob:none' unless unfiltered_clone?
      end

      def git_environment_variables
        vars = {
          GIT_TERMINAL_PROMPT: '0',
          GIT_CONFIG_NOSYSTEM: '1',
          GIT_AUTHOR_NAME: git_user_name(service_account),
          GIT_AUTHOR_EMAIL: git_user_email(service_account),
          GIT_COMMITTER_NAME: git_user_name(@current_user),
          GIT_COMMITTER_EMAIL: git_user_email(@current_user)
        }

        git_config = [
          ['safe.directory', '/builds/*'],
          ["url.#{Gitlab.config.gitlab.url}/.insteadOf", "git@#{URI.parse(Gitlab.config.gitlab.url).host}:"]
        ]

        if project.project_setting.dap_session_tracking_enabled?
          # Install a git hooks directory via GIT_CONFIG so that all git commands
          # (including those run via run_command / run_shell_command) pick up the
          # commit-msg hook that appends the session trailers.
          git_config << ['core.hooksPath', GIT_HOOKS_DIR]
        end

        # Tells the runner not to embed CI_JOB_TOKEN in clone URLs or insteadOf rules,
        # leaving the origin URL credential-free for the helper installed below.
        vars[:FF_GIT_URLS_WITHOUT_TOKENS] = 'true'

        # Path-scoped keys match without useHttpPath, so using the full instance URL
        # (including any relative-URL path) narrows the scope: the OAuth token is only
        # offered to the GitLab instance path, not to unrelated applications on the
        # same host. gitlab_origin (scheme+host) is kept for the helper's stdin check
        # because git sends the host (not the path) in the credential request.
        helper_key = "credential.#{Gitlab.config.gitlab.url}.helper"

        # An empty value resets the helper list at this scope, and it has to come first:
        # the Runner installs its own CI_JOB_TOKEN helper at this same scope, GIT_CONFIG_*
        # pairs apply after all config files, and git stops at the first helper that
        # yields a password - so without this the job token wins, and it cannot push.
        git_config << [helper_key, '']

        # Scoped to the instance URL rather than the bare credential.helper key, so
        # the token is only offered to GitLab and the reset leaves other hosts alone.
        git_config << [helper_key, self.class.git_credential_helper]

        # Authenticate proactively (first request, not after a 401). No-op on
        # git < 2.46, which silently ignores the key. Scoped to the GitLab host
        # so credentials are not sent proactively to other hosts (submodules,
        # LFS, bundle URIs) - matching the runner's FF_USE_GIT_PROACTIVE_AUTH.
        git_config << ["http.#{Gitlab.config.gitlab.url}.proactiveAuth", 'basic']

        git_config.each_with_index do |(key, value), index|
          vars[:"GIT_CONFIG_KEY_#{index}"] = key
          vars[:"GIT_CONFIG_VALUE_#{index}"] = value
        end

        vars.merge(GIT_CONFIG_COUNT: git_config.size.to_s)
      end

      def base_variables
        secure = Gitlab::DuoWorkflow::Client.secure?(feature_setting: feature_setting)

        base_variables = {
          DUO_WORKFLOW_ADDITIONAL_CONTEXT_CONTENT: serialized_flow_additional_context,
          DUO_WORKFLOW_BASE_PATH: './',
          DUO_WORKFLOW_DEFINITION: resolved_workflow_definition,
          **flow_config_variables,
          **flow_identity_variables,
          DUO_WORKFLOW_AGENTS: workspace_agents_json,
          DUO_WORKFLOW_GOAL: workflow_goal,
          DUO_WORKFLOW_SOURCE_BRANCH: resolve_source_branch,
          DUO_WORKFLOW_WORKFLOW_ID: String(@workflow.id),
          DUO_WORKFLOW_SERVICE_SERVER: duo_workflow_service_url,
          DUO_WORKFLOW_SERVICE_REALM: ::CloudConnector.gitlab_realm,
          DUO_WORKFLOW_GLOBAL_USER_ID: Gitlab::GlobalAnonymousId.user_id(@current_user),
          DUO_WORKFLOW_INSTANCE_ID: Gitlab::GlobalAnonymousId.instance_id,
          DUO_WORKFLOW_INSECURE: secure ? 'false' : 'true',
          DUO_WORKFLOW_DEBUG: Gitlab::DuoWorkflow::Client.debug_mode? ? 'true' : 'false',
          # Debug level logs every request the runner relays, model content included.
          LOG_LEVEL: @workflow.metadata_content_retention? ? 'info' : 'debug',
          DUO_WORKFLOW_GIT_HTTP_BASE_URL: Gitlab.config.gitlab.url,
          DUO_WORKFLOW_GIT_HTTP_USER: "oauth",
          DUO_WORKFLOW_GIT_USER_EMAIL: git_user_email(@current_user),
          DUO_WORKFLOW_GIT_USER_NAME: git_user_name(@current_user),
          DUO_WORKFLOW_GIT_AUTHOR_EMAIL: git_user_email(service_account),
          DUO_WORKFLOW_GIT_AUTHOR_USER_NAME: git_user_name(service_account),
          DUO_WORKFLOW_METADATA: workflow_metadata,
          DUO_WORKFLOW_PROJECT_ID: project.id,
          DUO_WORKFLOW_NAMESPACE_ID: project.root_namespace.id,
          GITLAB_BASE_URL: Gitlab.config.gitlab.url,
          GITLAB_PROJECT_PATH: project.full_path,
          AGENT_PLATFORM_GITLAB_VERSION: Gitlab.version_info.to_s,
          AGENT_PLATFORM_MODEL_METADATA: agent_platform_model_metadata_json,
          AGENT_PLATFORM_FEATURE_SETTING_NAME: feature_setting_name,
          GITLAB_ENABLE_GLOBAL_SKILLS: 'true',
          # The SRT sandbox mounts $HOME read-only, so the CLI cannot write its
          # bundled glab skill and default preloading is dropped. Naming the
          # skill explicitly preloads the globally installed copy instead;
          # duo-cli versions without skill support ignore this variable.
          GITLAB_DUO_SKILLS: 'glab',
          DUO_SESSION_TRACKING_ENABLED: project.project_setting.dap_session_tracking_enabled?.to_s,
          # The Duo Workflow executor image pins a specific glab version,
          # so glab's post-command "update available" nudge isn't actionable
          # for users. Silence it to avoid agents relaying misleading hints.
          GLAB_CHECK_UPDATE: '0'
        }

        base_variables[:LANGSMITH_TRACE] = @params[:langsmith_trace] if @params[:langsmith_trace].present?

        base_variables.merge(dynamic_suspension_variables)
      end

      # Same gate as the AI Gateway header in API::Helpers::DuoWorkflowHelpers#push_feature_flags. Every flow reads the
      # repository here. This stops in 19.7, when the Duo Workflow Service pulls the agents only for flows that need
      # them instead of Rails pushing them to every flow:
      # https://gitlab.com/groups/gitlab-org/modelops/applied-ml/code-suggestions/-/work_items/103
      # Memoized: base_variables runs twice.
      def workspace_agents_json
        enabled = Feature.enabled?(:dap_workspace_agents, @current_user)
        agents = enabled ? ::Gitlab::DuoWorkflow::WorkspaceAgentsReader.new(project).agents : []

        ::Gitlab::Json.dump(agents)
      end
      strong_memoize_attr :workspace_agents_json

      def workflow_goal
        @params[:goal]
      end

      # Must name the same flow as the workflow token, which DWS checks against them.
      def flow_identity_variables
        {
          DUO_WORKFLOW_FLOW_CONFIG_ID: @params[:flow_config_id],
          DUO_WORKFLOW_FLOW_CONFIG_SCHEMA_VERSION: @params[:flow_config_schema_version],
          DUO_WORKFLOW_FLOW_VERSION: @params[:flow_version]
        }
      end

      # The inline config stays as a fallback for a duo-cli too old to fetch the flow.
      # fetch_flow_config_fallback_commands clears whichever one the job does not use.
      def flow_config_variables
        variables = { DUO_WORKFLOW_FLOW_CONFIG: serialized_duo_flow_config }
        return variables unless @params[:fetch_flow_config]

        variables.merge(DUO_WORKFLOW_FETCH_FLOW_CONFIG: 'true')
      end

      def flow_config_echo_command
        @params[:fetch_flow_config] ? %(echo $DUO_WORKFLOW_FETCH_FLOW_CONFIG) : %(echo $DUO_WORKFLOW_FLOW_CONFIG)
      end

      def token_variables
        {
          GITLAB_OAUTH_TOKEN: @params[:workflow_oauth_token],
          DUO_WORKFLOW_SERVICE_TOKEN: workflow_service_token_variable,
          DUO_WORKFLOW_GIT_HTTP_PASSWORD: @params[:workflow_oauth_token],
          GITLAB_TOKEN: @params[:workflow_oauth_token],
          GIT_PASSWORD: @params[:workflow_oauth_token],
          # From glab 1.111.0, a token supplied via GITLAB_TOKEN is treated as a
          # PAT and sent as Private-Token unless the OAuth flag also comes from
          # the environment, which would 401 our OAuth token.
          GLAB_IS_OAUTH2: 'true'
        }
      end

      # The CLI never uses this value, but needs it set to run in CI mode.
      def workflow_service_token_variable
        if Feature.enabled?(:duo_workflow_ci_service_token_placeholder, project)
          DUO_WORKFLOW_SERVICE_TOKEN_PLACEHOLDER
        else
          @params[:workflow_service_token]
        end
      end

      def variables
        git_clone_variables
          .merge(base_variables)
          .merge(token_variables)
          .merge(git_environment_variables)
          .merge(sandbox.environment_variables)
      end

      def commands
        sandbox.setup_sandbox_commands +
          coding_environment_commands +
          git_hooks_setup_commands +
          executor_commands
      end

      def coding_environment_commands
        return [] if skip_coding_environment?

        git_strategy.clone_commands +
          setup_script_commands +
          remote_url_commands +
          workspace_fixup_commands
      end

      def executor_commands
        workflow_echo_commands + set_up_executor_commands
      end

      def workspace_fixup_commands
        [
          'cd "$CI_PROJECT_DIR"',
          # `git clone --revision` writes no fetch refspec, so `git fetch origin` would
          # update no remote-tracking refs. Idempotent on the init+fetch path.
          'git config remote.origin.fetch "+refs/heads/*:refs/remotes/origin/*"',
          # The runner checks out a detached HEAD at the commit SHA; re-attach to a named branch.
          'git checkout -B "${DUO_WORKFLOW_SOURCE_BRANCH:-$CI_DEFAULT_BRANCH}"',
          fetch_default_branch_command
        ]
      end

      # Base-branch diffs and rebases need the remote-tracking ref.
      def fetch_default_branch_command
        [
          'git fetch --no-tags', blob_none_filter, 'origin',
          '"+refs/heads/${CI_DEFAULT_BRANCH}:refs/remotes/origin/${CI_DEFAULT_BRANCH}"',
          '|| true'
        ].compact.join(' ')
      end

      def workflow_echo_commands
        [
          %(echo $DUO_WORKFLOW_DEFINITION),
          %(echo $DUO_WORKFLOW_FLOW_CONFIG_ID),
          %(echo $DUO_WORKFLOW_FLOW_VERSION),
          goal_echo_command,
          %(echo $DUO_WORKFLOW_SOURCE_BRANCH),
          flow_config_echo_command,
          %(echo $DUO_WORKFLOW_FLOW_CONFIG_SCHEMA_VERSION),
          # NOTE: Do not echo $DUO_WORKFLOW_ADDITIONAL_CONTEXT_CONTENT. It can carry
          # sensitive payloads (e.g. the raw secret for the secrets_fp_detection flow,
          # or diffs/file contents for other flows) and the job trace is readable by
          # low-privilege/anonymous users. See gitlab-org/gitlab#602194.
          %(echo Starting Workflow #{@workflow.id})
        ].compact
      end

      # Overridden to nil on the resume path, where the goal can carry a
      # user's free-text reply rather than this class's templated one; see
      # ResumeWorkflowService.
      def goal_echo_command
        %(echo $DUO_WORKFLOW_GOAL)
      end

      # Normalise origin before the flow runs.
      #
      # FF_GIT_URLS_WITHOUT_TOKENS only governs the URLs the runner builds itself; it
      # does not scrub CI_REPOSITORY_URL, which always embeds gitlab-ci-token:$CI_JOB_TOKEN
      # (Ci::Build#repo_url). A runner-side post_get_sources_script that resets origin to
      # CI_REPOSITORY_URL therefore reintroduces the job token after the runner set a
      # credential-free origin. Credentials in the URL take precedence over any credential
      # helper, and the job token cannot push, so the helper would never be consulted and
      # the push would 403. Point origin at a credential-free URL and let the helper
      # supply the OAuth token.
      def remote_url_commands
        [
          # -C: setup_script runs in this same shell and may have changed directory.
          'git -C "$CI_PROJECT_DIR" remote set-url origin ' \
            '"${DUO_WORKFLOW_GIT_HTTP_BASE_URL%/}/${GITLAB_PROJECT_PATH}.git"'
        ]
      end

      def set_up_executor_commands
        wrapped_commands = sandbox.wrap_command(executor_cli_command)

        cli_install_commands + fetch_flow_config_fallback_commands +
          glab_setup.commands + orbit_setup.commands + wrapped_commands
      end

      # A custom image can ship a duo-cli that has no --fetch-flow-config, so the job asks
      # the installed one. A duo that is missing or fails falls back to the inline config.
      # Exports to empty, not unset, because the sandbox passes every job variable on.
      def fetch_flow_config_fallback_commands
        return [] unless @params[:fetch_flow_config]

        [
          "if duo run --help 2>&1 | grep -q -- '--fetch-flow-config'; then " \
            'export DUO_WORKFLOW_FLOW_CONFIG=""; ' \
            'else echo "duo-cli cannot fetch the flow config, sending it inline"; ' \
            'export DUO_WORKFLOW_FETCH_FLOW_CONFIG=""; fi'
        ]
      end

      # Downloads the duo-cli binary for the runner OS and architecture from the
      # GitLab package registry, unless the image already ships `duo`. A trusted
      # runtime always installs the pinned binary and fails unless it is the one in PATH.
      def cli_install_commands
        registry_url = "#{DUO_CLI_REGISTRY_BASE_URL}/#{DUO_CLI_PROJECT_ID}" \
          "/packages/generic/duo-cli/#{DUO_CLI_VERSION}/${BINARY}"

        skip_if_present = [
          "command -v duo > /dev/null 2>&1 && ",
          "echo \"duo-cli already present, skipping installation\" || "
        ]

        binary_install_command = [
          *(skip_if_present unless gitlab_hosted_runner_only?),
          "{ ",
          curl_check_command,
          "OS=$(uname -s | tr '[:upper:]' '[:lower:]') && ",
          "ARCH=$(uname -m) && ",
          "case \"${ARCH}\" in x86_64|amd64) ARCH=x64 ;; arm64|aarch64) ARCH=arm64 ;; *) " \
            "echo \"Unsupported architecture: ${ARCH}\" && exit 1 ;; esac && ",
          "BINARY=\"duo-${OS}-${ARCH}\" && ",
          "DOWNLOAD_URL=\"#{registry_url}\" && ",
          "echo \"Downloading duo-cli #{DUO_CLI_VERSION} (${BINARY})...\" && ",
          "curl -fsSL \"${DOWNLOAD_URL}\" -o \"#{DUO_CLI_INSTALL_DIR}/duo\" && ",
          "chmod +x \"#{DUO_CLI_INSTALL_DIR}/duo\"; ",
          "} || exit 1"
        ].join

        [
          binary_install_command,
          gitlab_hosted_runner_only? ? installed_duo_check_command : %(which duo || echo "duo not in PATH"),
          %(duo --version || echo "duo version check failed")
        ]
      end

      # Fails with a clear message instead of `curl: command not found`, which is
      # what an image that relies on a skipped setup_script for curl would print.
      def curl_check_command
        message = 'curl is required to download duo-cli but is not in the image.'
        message += ' This flow skips setup_script, so add curl or duo to the image itself.' if skip_coding_environment?

        "command -v curl > /dev/null 2>&1 || { echo \"#{message}\"; exit 1; } && "
      end

      def installed_duo_check_command
        %([ "$(which duo)" = "#{DUO_CLI_INSTALL_DIR}/duo" ] || ) +
          %({ echo "duo resolves to $(which duo), not #{DUO_CLI_INSTALL_DIR}/duo"; exit 1; })
      end

      def executor_cli_command
        %(duo run --existing-session-id #{@workflow.id} --connection-type websocket)
      end

      def glab_setup
        @glab_setup ||= ::Gitlab::DuoWorkflow::GlabSetup.new(current_user: @current_user)
      end

      def orbit_setup
        @orbit_setup ||= ::Gitlab::DuoWorkflow::OrbitSetup.new(
          current_user: @current_user,
          checkout: !skip_coding_environment?
        )
      end

      def workflow_metadata
        # TODO: This is temporary workaround to pass model selection via
        # metadata into node executor to address
        # https://gitlab.com/gitlab-org/editor-extensions/gitlab-lsp/-/issues/1767
        # it will be cleaned up by
        # https://gitlab.com/gitlab-org/editor-extensions/gitlab-lsp/-/issues/1630
        ::Gitlab::Json.dump(
          ::Gitlab::Json.safe_parse(@params[:workflow_metadata]).merge(
            'modelMetadata' => agent_platform_model_metadata_json
          )
        )
      end

      def duo_workflow_service_url
        Gitlab::DuoWorkflow::Client.url_for(
          feature_setting: feature_setting,
          user: @current_user
        )
      end

      def project
        @workflow.project
      end

      def feature_setting
        @params.fetch(:duo_agent_platform_feature_setting, nil)
      end

      def feature_setting_name
        # If no feature setting is provided, use the default workflow feature name,
        # which is :duo_agent_platform.

        # All workflows originating from CI should have a feature setting name set.
        # This is because the value of the feature_setting_name is sent as `AGENT_PLATFORM_FEATURE_SETTING_NAME`
        # to the Node Executor. Node executor then sends this value to the websockets endpoint as the header
        # `X-Gitlab-Agent-Platform-Feature-Setting-Name`.

        # We expect all non-chat workflows to have a feature setting name set. Consequently, if this header
        # does not exist, we treat that request as a chat request, so it is essential to have the fallback to
        # workflow_feature_name, just in case.
        (feature_setting&.feature || ::Ai::ModelSelection::FeaturesConfigurable.workflow_feature_name).to_s
      end

      # Memoized: a workflow start reads it four times, and it can fetch the model definitions from AI Gateway.
      def agent_platform_model_metadata_json
        response = ::Gitlab::Llm::AiGateway::AgentPlatform::ModelMetadata.new(
          feature_setting: feature_setting,
          user: @current_user
        ).execute

        response.fetch(Gitlab::Llm::AiGateway::AgentPlatform::ModelMetadata::HEADER_KEY, nil)
      end
      strong_memoize_attr :agent_platform_model_metadata_json

      def link_composite_identity
        identity = ::Gitlab::Auth::Identity.fabricate(service_account)
        identity.link!(@current_user, context: :permission_check) if identity&.composite?
      end

      def serialized_duo_flow_config
        return unless @params[:flow_config].present? && @params[:flow_config].is_a?(Hash)

        ::Gitlab::Json.dump(@params[:flow_config])
      end

      def serialized_flow_additional_context
        context = Ai::DuoWorkflows::BuildAdditionalContextService.new(
          standard_context_params: {
            project: project,
            current_user: @current_user,
            service_account: service_account,
            source_branch: @params.fetch(:source_branch, nil),
            session_url: @workflow.web_url,
            ref: @ref
          },
          trigger_params: {
            event_type: @params[:event_type],
            triggering_conversation: @params[:triggering_conversation]
          },
          additional_context: @params[:additional_context],
          client_context: @params[:client_context],
          resource: workflow_resource,
          foundational_flow: @workflow.foundational_flow,
          goal: workflow_goal
        ).execute.payload[:context]

        ::Gitlab::Json.dump(context)
      end

      # pipeline_links: fix_pipeline; resource: code_review/workplan/etc; goal: vulnerability flows.
      def workflow_resource
        @workflow.pipeline_links.link_type_source.first&.pipeline ||
          @workflow.resource ||
          resolve_vulnerability_resource
      end

      def resolve_vulnerability_resource
        return unless ::Vulnerabilities::TriggeredWorkflow::WORKFLOW_DEFINITIONS_TO_NAMES
                        .key?(@workflow.workflow_definition)

        vulnerability = project.vulnerabilities.find_by_id(@params[:goal])
        return unless vulnerability && Ability.allowed?(@current_user, :read_vulnerability, vulnerability)

        vulnerability
      end

      def git_user_email(user)
        return "" unless user.respond_to?(:commit_email_or_default)

        user.commit_email_or_default
      end

      def git_user_name(user)
        return "" unless user.respond_to?(:name)

        user.name
      end

      # Returns the source branch to use for the workflow. Falls back to the
      # project's default branch when the requested source branch is blank or no
      # longer exists (for example, a merged MR whose source branch was deleted).
      def resolve_source_branch
        source_branch = @params.fetch(:source_branch, nil)
        return project.default_branch_or_main if source_branch.blank?

        project.repository.branch_exists?(source_branch) ? source_branch : project.default_branch_or_main
      end

      def create_workload_branch
        workload_branch_service = ::Ci::Workloads::WorkloadBranchService.new(
          current_user: service_account,
          project: project,
          source_branch: @params.fetch(:source_branch, nil)
        )
        workload_branch_service.execute
      end
    end
  end
end
