# frozen_string_literal: true

require 'shellwords'

module Gitlab
  module DuoWorkflow
    # Service responsible for configuring SRT (Secure Runtime) sandbox for Duo Workflow execution
    # This class configures network firewall and filesystem restrictions for DAP ambient sessions.
    class Sandbox
      # Protected directory for platform-internal files (e.g. srt-settings.json).
      # Uses /var/tmp (world-writable, sticky bit) so any user - root or non-root -
      # can create the directory without elevated privileges. This avoids permission
      # errors on hardened images that run as a non-root UID.
      # The agent is explicitly denied write access via SRT's denyWrite rule.
      SANDBOX_SYSTEM_DIR = "/var/tmp/.gitlab-sandbox"

      # TLS, proxy, and locale variables forwarded into the sandbox so
      # self-managed instances behind private CAs or proxies keep working, and
      # tools keep the image's locale instead of falling back to US-ASCII;
      # `env -i` strips everything not listed here. Forwarded only when set: SRT
      # reads the upstream proxy with `HTTPS_PROXY ?? https_proxy`, so an empty
      # HTTPS_PROXY would hide a lowercase https_proxy.
      # NODE_TLS_REJECT_UNAUTHORIZED is deliberately excluded: it disables TLS
      # verification.
      FORWARDED_ENV_VARS = %w[
        NODE_EXTRA_CA_CERTS
        HTTP_PROXY
        HTTPS_PROXY
        NO_PROXY
        http_proxy
        https_proxy
        no_proxy
        LANG
        LC_ALL
      ].freeze

      def initialize(current_user:, duo_workflow_service_url:, duo_config:, project: nil, unmask_env_variables: [])
        @current_user = current_user
        @duo_workflow_service_url = duo_workflow_service_url
        @duo_config = duo_config
        @project = project
        @unmask_env_variables = unmask_env_variables
      end

      # Wraps a command with SRT sandbox if enabled.
      #
      # Without SRT, or when its pre-check fails, the command runs unsandboxed unless
      # the top-level group or instance sets require_sandbox. That setting is never
      # read from agent-config.yml, so a project cannot opt out.
      #
      # At runtime the script probes which unshare mode is available and stores
      # the result in $SANDBOX_UNSHARE.  The same prefix is applied to both the
      # SRT capability pre-check and the real run so that a failing unshare is
      # detected early rather than silently skipped.
      #
      # Probe order (first success wins):
      #   1. unshare -m true   - mount namespace only; works as root / CAP_SYS_ADMIN
      #                          (default image, SaaS path - byte-for-byte unchanged)
      #   2. unshare -rm true  - user + mount namespace; works for non-root with
      #                          unprivileged user-namespace support (hardened image,
      #                          UID 1001).  unshare -r maps UID 1001 to root *inside*
      #                          the new user namespace only; it grants no host
      #                          privilege and maps back to UID 1001 on the host.
      #   3. (empty)           - no namespace wrapper; fail-open fallback
      #
      # Probe order rationale: trying -m first means root (SaaS) resolves to -m,
      # preserving the existing SaaS behaviour exactly.  Non-root (hardened image)
      # falls through to -rm because -m fails without CAP_SYS_ADMIN.
      #
      # @param command [String] The command to wrap
      # @return [Array<String>] Array with shell commands
      def wrap_command(command)
        srt_settings_path = "#{SANDBOX_SYSTEM_DIR}/srt-settings.json"
        env_vars_flags = "#{build_env_vars_flags} #{build_forwarded_env_vars_flags}"
        require_sandbox = parent_settings.require_sandbox
        [
          %(if which srt > /dev/null; then),
          %(  echo "SRT found, creating config..."),
          %(  echo #{Shellwords.escape(Gitlab::Json.dump(srt_config))} > #{srt_settings_path}),
          %(  echo "Testing SRT sandbox capabilities..."),
          %(  if unshare -m true 2>/dev/null; then),
          %(    SANDBOX_UNSHARE="unshare -m"),
          %(  elif unshare -rm true 2>/dev/null; then),
          %(    SANDBOX_UNSHARE="unshare -rm"),
          %(  else),
          %(    SANDBOX_UNSHARE=""),
          %(  fi),
          %(  if $SANDBOX_UNSHARE srt --settings #{srt_settings_path} true 2>/dev/null; then),
          %(    echo "SRT sandbox test successful, running command: #{command}"),
          %(    export GITLAB_WORKFLOW_SANDBOX=true),
          %(    $SANDBOX_UNSHARE env -i #{env_vars_flags} srt --settings #{srt_settings_path} #{command}),
          %(  else),
          *srt_unavailable_commands(command, required: require_sandbox,
            reason: "SRT found but can't create sandbox (insufficient privileges)", indent: '    '),
          %(  fi),
          %(else),
          *srt_unavailable_commands(command, required: require_sandbox,
            reason: 'srt is not installed or not in PATH', indent: '  '),
          %(fi),
          %(echo "Command execution completed with exit code: $?")
        ]
      end

      def environment_variables
        {
          NPM_CONFIG_CACHE: "/tmp/.npm-cache",
          GITLAB_LSP_STORAGE_DIR: "/tmp/gitlab-lsp",
          GITLAB_BIN_DIR: "/tmp/gitlab-bin",
          ORBIT_DATA_DIR: "/tmp/orbit",
          # The sandbox blocks the collector, so every call would log a failed send.
          ORBIT_TELEMETRY_ENABLED: "false",
          GLAB_CONFIG_DIR: "#{SANDBOX_SYSTEM_DIR}/glab-cli",
          TMPDIR: "/tmp",
          # srt overrides the child's TMPDIR to /tmp/claude and never creates it,
          # so TMPDIR above is ignored and mktemp fails inside the sandbox. srt
          # honors CLAUDE_CODE_TMPDIR first, so pin it to the existing /tmp.
          CLAUDE_CODE_TMPDIR: "/tmp"
        }
      end

      # /var/tmp is shared, so another user could create SANDBOX_SYSTEM_DIR
      # first, and `mkdir -p` would accept it. Stop unless it is a real
      # directory owned by the current user, and keep it owner-only.
      def setup_sandbox_commands
        dir = SANDBOX_SYSTEM_DIR

        [
          %(mkdir -p -m 700 #{dir} && [ ! -L #{dir} ] && [ -O #{dir} ] && chmod 700 #{dir} || ) +
            %({ echo "#{dir} is not a directory owned by the current user" >&2; exit 1; })
        ]
      end

      private

      # Builds environment variable flags for unshare command
      # Uses variable references (e.g., $VAR) instead of embedding values to avoid logging sensitive data
      # Combines passed variables with sandbox-specific environment variables
      # @return [String] Environment variable flags formatted for unshare command
      def build_env_vars_flags
        all_vars = @unmask_env_variables + environment_variables.keys + %w[PATH HOME GITLAB_WORKFLOW_SANDBOX]
        all_vars.uniq.map { |var| "#{var}=\"$#{var}\"" }.join(' ')
      end

      # ${VAR+...} expands to nothing when VAR is unset, so unset variables stay unset
      # @return [String] Environment variable flags for FORWARDED_ENV_VARS
      def build_forwarded_env_vars_flags
        FORWARDED_ENV_VARS.map { |var| "${#{var}+#{var}=\"$#{var}\"}" }.join(' ')
      end

      # Commands for when SRT cannot sandbox the command.
      #
      # @param command [String] The command to run when the sandbox is not required
      # @param required [Boolean] Whether the top-level group or instance requires the sandbox
      # @param reason [String] Why the sandbox is unavailable
      # @param indent [String] Indentation for each line
      # @return [Array<String>] Array with shell commands
      def srt_unavailable_commands(command, required:, reason:, indent:)
        commands =
          if required
            [
              %(echo "Error: #{reason}, refusing to run because the sandbox is required"),
              %(echo "For more details visit: #{configure_runners_docs_url}"),
              %(exit 1)
            ]
          else
            [
              %(echo "Warning: #{reason}, running command directly without sandbox"),
              %(echo "For more details visit: #{configure_runners_docs_url}"),
              command
            ]
          end

        commands.map { |line| "#{indent}#{line}" }
      end

      def configure_runners_docs_url
        Rails.application.routes.url_helpers.help_page_url(
          'user/duo_agent_platform/flows/execution/_index.md', anchor: 'configure-runners-to-execute-flows'
        )
      end

      # Returns parent AI settings: namespace-level (SaaS TLG) or instance-level (self-managed).
      # @return [Ai::NamespaceSetting, Ai::Setting]
      def parent_settings
        return @project.root_ancestor.ai_settings if ::Gitlab::Saas.feature_available?(:gitlab_com_subscriptions)

        # rubocop:disable Gitlab/AvoidUserOrganization -- fallback for project-less workflows; in Cells 1.0 a user belongs to exactly one organization
        organization = @project&.organization || @current_user.organization
        # rubocop:enable Gitlab/AvoidUserOrganization

        return ::Ai::Setting.new unless organization

        ::Ai::Setting.for_organization_read_only(organization)
      end

      # Generates SRT configuration for network and filesystem restrictions
      # @return [Hash] SRT configuration
      def srt_config
        # Combine top-level parent and project settings
        inherited_settings = parent_settings
        combined_settings = combine_settings(inherited_settings)
        effective_allowed = combined_settings[:allow_list]
        effective_denied = combined_settings[:deny_list]
        allow_all_unix_sockets = combined_settings[:allow_all_unix_sockets]

        allowed_domains = (minimal_allowlisted_domains + effective_allowed).compact.uniq
        denied_domains = effective_denied.compact.uniq
        {
          network: {
            allowedDomains: allowed_domains,
            deniedDomains: denied_domains,
            allowAllUnixSockets: !!allow_all_unix_sockets
          },
          filesystem: {
            denyRead: ["~/.ssh"],
            allowWrite: ["./", "/tmp"],
            denyWrite: [SANDBOX_SYSTEM_DIR],
            allowGitConfig: true
          }
        }
      end

      # Combines settings that are inherited from top-level group or instance,
      # with the settings specified in a project's agent-config.yml file:
      #   * A project can always extend the inherited deny list
      #   * A project can only add to the inherited allow-list if the parent has set allow_project_extension
      #   * For allow_all_unix_sockets and include_recommended_allowed:
      #     * With allow_project_extension: project can set either value freely
      #     * Without allow_project_extension: project can only tighten (set false when inherited is true);
      #       loosening (set true when inherited is false) is not permitted
      def combine_settings(inherited_settings)
        # Project-level settings:
        duo_config_allow_all_unix_sockets = load_duo_config_all_unix_sockets
        duo_config_allow_domains, duo_config_deny_domains = load_duo_config_domains
        duo_config_include_recommended = load_duo_config_include_recommended_allowed

        # Inherited settings:
        allow_project_extension = inherited_settings.allow_project_extension
        effective_allowed = inherited_settings.allowed_domains.to_a.dup
        effective_denied = inherited_settings.denied_domains.to_a.dup
        effective_allow_all_unix_sockets = inherited_settings.allow_all_unix_sockets
        effective_include_recommended_allowed = inherited_settings.include_recommended_allowed

        if allow_project_extension
          # Flexible mode: project can extend the allowlist and add to the denylist
          effective_allowed += duo_config_allow_domains
          effective_denied += duo_config_deny_domains

          unless duo_config_include_recommended.nil?
            effective_include_recommended_allowed = duo_config_include_recommended
          end

          unless duo_config_allow_all_unix_sockets.nil?
            effective_allow_all_unix_sockets = duo_config_allow_all_unix_sockets
          end
        else
          # Strict mode: project cannot loosen settings (allowlist and loosening booleans are ignored);
          # project denylist additions are always honored (more restrictive is allowed).
          # Boolean settings can only be overridden by tightening: project can set false when inherited is true.
          effective_denied += duo_config_deny_domains

          effective_include_recommended_allowed =
            tighten(effective_include_recommended_allowed, duo_config_include_recommended)
          effective_allow_all_unix_sockets =
            tighten(effective_allow_all_unix_sockets, duo_config_allow_all_unix_sockets)
        end

        effective_allowed += NetworkPolicyDomains.recommended_allowed_domains if effective_include_recommended_allowed

        effective_allowed = effective_allowed.compact.uniq
        effective_denied = effective_denied.compact.uniq

        {
          allow_list: effective_allowed,
          deny_list: effective_denied,
          allow_all_unix_sockets: effective_allow_all_unix_sockets
        }
      end

      # Returns the project value only if it represents a tightening change (strict mode only).
      # In strict mode, a project can only disable a setting, never enable it.
      # @param inherited_value [Boolean, nil] The inherited boolean value
      # @param project_value [Boolean, nil] The project-level boolean value
      # @return [Boolean, nil] The effective value after applying tightening rules
      def tighten(inherited_value, project_value)
        return inherited_value if project_value.nil?
        return inherited_value if project_value && !inherited_value # would loosen - ignore

        project_value
      end

      # Returns list of required domains allowed for network access
      # @return [Array<String>] Allowed domains
      def minimal_allowlisted_domains
        [
          "host.docker.internal",
          "localhost",
          extract_domain(Gitlab.config.gitlab.url),
          "*.#{extract_domain(Gitlab.config.gitlab.url)}",
          extract_domain(@duo_workflow_service_url)
        ]
      end

      def load_duo_config_all_unix_sockets
        network_policy = @duo_config.network_policy
        return unless network_policy

        network_policy.fetch("allow_all_unix_sockets", nil)
      end

      def load_duo_config_include_recommended_allowed
        network_policy = @duo_config.network_policy
        return unless network_policy

        network_policy.fetch("include_recommended_allowed", nil)
      end

      def load_duo_config_domains
        network_policy = @duo_config.network_policy
        return [[], []] unless network_policy

        allowed_domains = network_policy.fetch("allowed_domains", [])
        denied_domains = network_policy.fetch("denied_domains", [])

        [allowed_domains, denied_domains]
      end

      # Extracts domain from a URL
      # @param url [String] URL to extract domain from
      # @return [String, nil] Extracted domain
      def extract_domain(url)
        return url if url.blank?

        # Try parsing as a full URI first
        uri = URI.parse(url)
        return uri.host if uri.host

        # If no host found, try parsing as just host:port by prepending //
        uri = URI.parse("//#{url}")
        uri.host
      rescue URI::InvalidURIError
        # Fallback: if it contains a colon, assume it's host:port
        url.include?(':') ? url.split(':').first : url
      end
    end
  end
end
