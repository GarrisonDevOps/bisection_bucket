# frozen_string_literal: true

module Ai
  module ToolRules
    # Resolves the admin tool rules that govern a Duo Workflow session. Shared by the session
    # token claim and the session approval check, so both resolve rules the same way.
    class SessionPolicyService
      EMPTY_TOOL_POLICIES = {
        pre_approved_tools: [].freeze, denied_tools: [].freeze, ask_tools: [].freeze
      }.freeze

      def initialize(container:, surface:)
        @container = container
        @surface = surface
      end

      # @return [Hash] the ResolutionService payload, or EMPTY_TOOL_POLICIES when there is no
      #   container, the session is ungoverned, or resolution fails
      def execute
        return EMPTY_TOOL_POLICIES unless @container
        return EMPTY_TOOL_POLICIES if GovernanceSurface.ungoverned?(@surface)

        result = ResolutionService.new(
          namespace: @container.root_ancestor,
          surface: @surface,
          project: @container.is_a?(::Project) ? @container : nil
        ).execute

        result.success? ? result.payload : EMPTY_TOOL_POLICIES
      end
    end
  end
end
