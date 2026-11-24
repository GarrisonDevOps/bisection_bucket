# frozen_string_literal: true

module Ai
  module DuoSettings
    # Assembles the flow settings of a group's GitLab Duo settings page as the data attributes the
    # page reads: which Agent Platform features the group allows, the foundational flows the page
    # lists and selects, and the template project. The helper hands in the presenter that picks
    # the flows and renders the result.
    class FlowsSettingsSerializer
      include ::MarkupHelper

      # @param group [Group]
      # @param current_user [User] the viewer, for whom the flow descriptions render
      # @param flows [Ai::DuoSettings::FoundationalFlowsPresenter] decides which flows the page lists
      def initialize(group, current_user:, flows:)
        @group = group
        @current_user = current_user
        @flows = flows
      end

      # @return [Hash{Symbol => String, nil}]
      def settings
        data = {
          duo_enterprise_active: root_ancestor.has_active_add_on_purchase?([:duo_enterprise]).to_s,
          code_review_flow_consent_given: root_ancestor.consented_to?(:code_review_flow_dap_routing).to_s,
          duo_remote_flows_availability: namespace_settings.duo_remote_flows_availability.to_s,
          duo_foundational_flows_availability: namespace_settings.duo_foundational_flows_availability.to_s,
          duo_scheduled_triggers_availability: namespace_settings.duo_scheduled_triggers_availability.to_s,
          duo_custom_agents_availability: namespace_settings.duo_custom_agents_availability.to_s,
          duo_custom_flows_availability: namespace_settings.duo_custom_flows_availability.to_s,
          duo_external_agents_availability: namespace_settings.duo_external_agents_availability.to_s,
          tool_approval_for_session_availability: namespace_settings.tool_approval_for_session_availability.to_s,
          available_foundational_flows: available_foundational_flows_json,
          selected_foundational_flow_references: ::Gitlab::Json.generate(flows.selected_flow_references),
          group_is_root: group.root?.to_s,
          duo_template_project: duo_template_project_json,
          show_duo_template_project: show_duo_template_project_json
        }

        data[:duo_auto_mode_availability] = namespace_settings.duo_auto_mode_availability.to_s if duo_auto_mode_enabled?

        data
      end

      # Whether the page shows the auto mode setting. The helper gates its cascading popover on it too.
      #
      # @return [Boolean]
      def duo_auto_mode_enabled?
        ::Feature.enabled?(:duo_auto_mode, root_ancestor)
      end

      private

      attr_reader :group, :current_user, :flows

      def available_foundational_flows_json
        ::Gitlab::Json.generate(
          flows.listed_flows.map do |item|
            {
              name: item.translated_display_name,
              description: item.translated_description,
              descriptionHtml: markdown(item.translated_description, project: nil, group: group),
              reference: item.foundational_flow_reference
            }
          end
        )
      end

      def duo_template_project_json
        return unless group.root?

        project = group.namespace_template_setting&.duo_template_project
        return unless project

        {
          id: project.id,
          name: project.name,
          name_with_namespace: project.name_with_namespace,
          full_path: project.full_path,
          avatar_url: project.avatar_url
        }.to_json
      end

      def show_duo_template_project_json
        (group.root? && root_ancestor.id.present?).to_json
      end

      def namespace_settings
        group.namespace_settings
      end

      def root_ancestor
        group.root_ancestor
      end
    end
  end
end
