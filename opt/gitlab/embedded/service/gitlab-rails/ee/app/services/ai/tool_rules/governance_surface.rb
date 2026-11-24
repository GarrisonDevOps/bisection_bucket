# frozen_string_literal: true

module Ai
  module ToolRules
    # Resolves the governance surface: a surface, `nil` to use the caller's default,
    # or UNGOVERNED when this session must not be governed at all.
    module GovernanceSurface
      WEB = :web
      BACKGROUND = :background

      LOCAL = :local

      # A local surface with `duo_workflow_local_tool_governance` off. Distinct from
      # `nil`, which only means "use the caller's default". Callers must check
      # `ungoverned?` and skip resolving; ResolutionService is a backstop, not the guard.
      UNGOVERNED = :ungoverned

      REFUSED = :refused

      # `web` and `ambient` are both background environments (`web` is the legacy
      # form of `ambient`); keying off both reaches the Duo Developer flow, stored
      # as `web`, without a catalog relabel.
      BACKGROUND_ENVIRONMENTS = %w[web ambient].freeze

      # Limits background governance to these flows while the flag rolls out, so other
      # background flows stay unaffected. Remove at GA. Matched by reference base name
      # (`developer/v1` -> `developer`) so a flow version bump does not silently drop governance.
      ALLOWLISTED_FLOWS = %w[developer].freeze

      # Environments with confirmed local-surface semantics. `external` is excluded
      # because its semantics are unconfirmed; it keeps today's web behavior.
      LOCAL_ENVIRONMENTS = %w[ide chat chat_partial].freeze

      def self.from_environment(environment, container:, workflow_definition: nil)
        self.for(environment: environment, container: container, workflow_definition: workflow_definition) || WEB
      end

      def self.for(environment:, container:, workflow_definition: nil)
        background_surface(environment, container, workflow_definition) ||
          local_surface(environment, container)
      end

      def self.ungoverned?(surface)
        surface == UNGOVERNED
      end

      def self.refused?(surface)
        surface == REFUSED
      end

      # Shared by enforcement, the settings page and the project-rule check, so all three agree.
      #
      # @param namespace [Namespace, nil] checked on its root ancestor
      # @return [Boolean] whether un-ruled background tools default to deny
      def self.background_fail_closed?(namespace)
        root = namespace&.root_ancestor

        Feature.enabled?(:duo_workflow_background_tool_governance, root) &&
          Feature.enabled?(:duo_workflow_background_fail_closed, root)
      end

      # Shared by enforcement and the project-rule check, so both deny the same tools.
      #
      # @param tool_name [String]
      # @param mcp_tools [Ai::ToolRules::GovernedMcpTools, nil]
      # @param first_party_tools [Ai::ToolRules::FirstPartyTools, nil]
      # @return [Boolean] whether fail-closed denies the tool when the group sets no background value
      def self.fail_closed_denies?(tool_name, mcp_tools:, first_party_tools: nil)
        default = ::Ai::ToolRules::Registry.default_permission_of(
          tool_name, mcp_tools: mcp_tools, first_party_tools: first_party_tools
        )

        ::Ai::ToolRules::Permissions.background_effective(default, fail_closed: true) ==
          ::Ai::ToolRules::Permissions::DENY
      end

      def self.background_surface(environment, container, workflow_definition)
        return unless BACKGROUND_ENVIRONMENTS.include?(environment.to_s)

        flow = ::Ai::Catalog::FoundationalFlow.find_by_reference(workflow_definition.to_s)
        return unless flow && ALLOWLISTED_FLOWS.include?(flow.foundational_flow_reference.split('/').first)

        # Check the flag on the root ancestor so it applies to all subgroups and projects.
        return unless Feature.enabled?(:duo_workflow_background_tool_governance, container&.root_ancestor)

        BACKGROUND
      end
      private_class_method :background_surface

      # Local environments (ide, chat, ...) resolve as their own surface so
      # ToolRule#access_for applies local_access instead of web_access.
      def self.local_surface(environment, container)
        env = environment.to_s
        return unless LOCAL_ENVIRONMENTS.include?(env)
        return UNGOVERNED unless Feature.enabled?(:duo_workflow_local_tool_governance, container&.root_ancestor)

        env.to_sym
      end
      private_class_method :local_surface
    end
  end
end
