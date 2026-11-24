# frozen_string_literal: true

module Ai
  module Catalog
    module Flows
      # The rules an AI Catalog agent must pass to run as a subagent of a flow.
      # The save path (ReferenceResolver) and the execution path
      # (ResolveWorkflowItemsService) share them, so a rule added here applies
      # to both. refusal_code is the only public entry point for that reason.
      class ReferenceChecks
        # The user-facing sentence for a refusal code. The save path and the
        # execution path show the same sentence for the same rule. An unknown
        # item is identified by id, because the user may not be allowed to see
        # its name. Every other refusal is of an item the user can read.
        def self.refusal_message(code, id:, version:, name: nil)
          case code
          when :unknown_item
            format(
              s_("AICatalog|Agent '%{id}' (version %{version}) was not found or you do not have access to it"),
              id: id, version: version
            )
          when :location
            format(s_("AICatalog|Agent '%{name}' is not visible to flows in this project"), name: name)
          when :visibility
            format(
              s_("AICatalog|Agent '%{name}' must be at least as visible as the flow that references it"),
              name: name
            )
          when :unknown_version
            format(s_("AICatalog|Agent '%{name}' has no version %{version}"), name: name, version: version)
          when :custom_agents_disabled
            format(s_("AICatalog|Agent '%{name}' is a custom agent, and custom agents are turned off"), name: name)
          else
            format(
              s_("AICatalog|Agent '%{id}' (version %{version}) cannot be used in this flow"),
              id: id, version: version
            )
          end
        end

        def initialize(user:, flow_project:, flow_visibility:)
          @user = user
          @flow_project = flow_project
          @flow_visibility = flow_visibility
        end

        # Returns nil when the agent passes every rule, or the first rule it fails.
        #
        # :unknown_item    not an agent, deleted, or the user cannot read it
        # :location        a private agent outside the flow's project, a restricted
        #                  agent outside the flow's root group, or a namespace restriction
        # :visibility      the agent is less visible than the flow that references it
        # :unknown_version no released version of that number
        def refusal_code(item, version)
          return :unknown_item unless readable_agent?(item)
          return :location unless location_permits?(item)
          return :visibility unless as_visible_as_flow?(item)
          return :unknown_version unless version.present? && version.released?

          nil
        end

        private

        attr_reader :user, :flow_project, :flow_visibility

        def readable_agent?(item)
          item.present? && item.agent? && !item.deleted? &&
            Ability.allowed?(user, :read_ai_catalog_item, item)
        end

        def location_permits?(item)
          return false if item.blocked_by_namespace_restriction?(flow_project)
          return true if item.visibility_public?
          return item.project_id == flow_project.id if item.visibility_private?

          item.project.present? && item.project.root_ancestor.id == flow_project.root_ancestor.id
        end

        def as_visible_as_flow?(item)
          item.at_least_as_visible_as?(flow_visibility)
        end
      end
    end
  end
end
