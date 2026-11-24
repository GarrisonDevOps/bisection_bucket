# frozen_string_literal: true

module Ai
  module DuoSettings
    # Foundational flows on a group's GitLab Duo settings page.
    class FoundationalFlowsPresenter
      # @param group [Group]
      def initialize(group)
        @group = group
      end

      # Whether the group readiness card renders. The flag rolls out per top-level group.
      #
      # @return [Boolean]
      def readiness_card_enabled?
        ::Feature.enabled?(:duo_group_agent_readiness_settings, root_ancestor, type: :beta)
      end

      # The flows the settings page lists. Only the top-level group picks flows, so a subgroup lists the
      # ones it picked, and none without the readiness card.
      #
      # @return [Array<Ai::Catalog::FoundationalFlow>]
      def listed_flows
        return available_flows if group.root?
        return [] unless readiness_card_enabled?

        selected_flows
      end

      # The flows the top-level group picked, which its subgroups and projects list read-only.
      #
      # @return [Array<Ai::Catalog::FoundationalFlow>]
      def selected_flows
        picked_references = root_ancestor.selected_foundational_flow_references
        available_flows.select { |flow| picked_references.include?(flow.foundational_flow_reference) }
      end

      # The group's own selection, which the settings page sends back on save. A subgroup's stays empty
      # so that saving keeps its top-level group's flows. With the readiness card on, it leaves out a flow
      # that the settings block, so the next save drops it, but keeps a flow that only the lookup hides.
      #
      # @return [Array<String>] foundational flow references
      def selected_flow_references
        return [] unless group.root?
        return group.selected_foundational_flow_references unless readiness_card_enabled?

        group.selected_foundational_flow_references & settings_allowed_flow_references
      end

      private

      attr_reader :group

      def available_flows
        flows = ::Ai::Catalog::FoundationalFlow.available_for_group(root_ancestor)
        # Such a flow has nothing to turn on here while `slack_duo_group` is on, see SyncFoundationalFlowsService.
        return flows unless ::Integrations::SlackWorkspace::Workspace.duo_group_feature_enabled?(root_ancestor)

        flows.select(&:requires_enablement)
      end

      def settings_allowed_flow_references
        ::Ai::Catalog::FoundationalFlow.all
          .select { |flow| flow.available_by_settings_for?(root_ancestor) }
          .map(&:foundational_flow_reference)
      end

      def root_ancestor
        group.root_ancestor
      end
    end
  end
end
