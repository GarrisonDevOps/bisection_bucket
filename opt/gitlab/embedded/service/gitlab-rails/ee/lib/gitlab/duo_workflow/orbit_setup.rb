# frozen_string_literal: true

module Gitlab
  module DuoWorkflow
    # Builds the shell commands that give a Duo Agent Platform workload its
    # Orbit skill. Runs after {GlabSetup}.
    #
    # With a checkout and +duo_developer_orbit+ on, orbit-cli installs its
    # skill and indexes the checkout, so the agent has a branch-aware
    # knowledge graph before it starts. Local Orbit needs no Orbit entitlement.
    # The index goes under ORBIT_DATA_DIR, set by {Sandbox#environment_variables}.
    # Otherwise the workload gets glab's remote Orbit skill when remote Orbit is
    # available.
    #
    # Best-effort: failures are logged as warnings and never abort the
    # workload.
    class OrbitSetup
      attr_reader :current_user

      # @param checkout [Boolean] whether the workload has a checkout of the project
      def initialize(current_user:, checkout:)
        @current_user = current_user
        @checkout = checkout
      end

      def commands
        if local_orbit?
          [local_orbit_command]
        elsif remote_orbit_available?
          [remote_skill_command]
        else
          []
        end
      end

      private

      def local_orbit?
        @checkout && Feature.enabled?(:duo_developer_orbit, current_user)
      end

      # Matches the gate the remote Orbit MCP tools use.
      def remote_orbit_available?
        ::Ai::Orbit::Settings.foundational_enabled?(current_user)
      end

      # Without remote Orbit, the env prefix keeps setup local; older orbit-cli ignores
      # ORBIT_NO_GITLAB. The first --yes lets glab install orbit, the second skips orbit's
      # agent picker.
      # workspace index --async (orbit-cli 0.160.0+) indexes in the background so the
      # agent starts at once. If it fails (for example an older orbit-cli rejects it),
      # fall back to the blocking index.
      def local_orbit_command
        local_only_env = 'GITLAB_TOKEN= ORBIT_NO_GITLAB=1 ' unless remote_orbit_available?

        <<~SH.strip
          if #{local_only_env}glab orbit --yes setup duo --yes --skip instructions --no-index; then
            glab orbit --yes workspace index --async . || glab orbit --yes index . || echo "Warning: Orbit local indexing failed; continuing without local index" >&2
          else
            echo "Warning: Orbit setup failed; continuing without the orbit skill and local index" >&2
          fi
        SH
      end

      # --force keeps the step idempotent across re-runs.
      def remote_skill_command
        warning = 'Warning: Orbit skill install failed; continuing without the orbit skill'

        %(glab skills install --global --force orbit || echo "#{warning}")
      end
    end
  end
end
