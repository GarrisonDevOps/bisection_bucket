# frozen_string_literal: true

module Ai
  module Catalog
    class ItemPolicy < ::BasePolicy
      condition(:third_party_flows_enabled, scope: :user) do
        ::Feature.enabled?(:ai_catalog_third_party_flows, @user)
      end

      condition(:ai_catalog_available_for_user, scope: :user) do
        # Currently this maps to duo_agent_platform, but makes it easier to implement granular controls down the road
        # We could also add one for ai_catalog_flows, but since it's not granular if the user does not have access to
        # duo agent platform, they won't have access to anything
        # When anonymous user, delegates to the other setting controls.
        @user.nil? || @user.allowed_to_use_through_namespace?(:ai_catalog)
      end

      condition(:project_ai_catalog_available) do
        @subject.project && ::Ai::Catalog.available_for_project?(@subject.project)
      end

      condition(:flows_available, scope: :subject) do
        @subject.project && ::Gitlab::Llm::StageCheck.available?(@subject.project, :ai_catalog_flows)
      end

      condition(:third_party_flows_available, scope: :subject) do
        @subject.project && ::Gitlab::Llm::StageCheck.available?(@subject.project, :ai_catalog_third_party_flows)
      end

      condition(:is_project_member) do
        @user && @subject.project&.member?(@user)
      end

      condition(:can_read_item_project) do
        @subject.project && can?(:read_project, @subject.project)
      end

      condition(:can_read_item_root_group) do
        @subject.project && can?(:read_group, @subject.project.root_ancestor)
      end

      condition(:can_admin_ai_catalog_item) do
        can?(:admin_ai_catalog_item, @subject.project)
      end

      condition(:public_item, scope: :subject, score: 0) do
        @subject.visibility_public?
      end

      condition(:restricted_item, scope: :subject, score: 0) do
        @subject.visibility_restricted?
      end

      condition(:deleted_item, scope: :subject, score: 0) do
        @subject.deleted?
      end

      condition(:flow) do
        @subject.flow?
      end

      condition(:third_party_flow) do
        @subject.third_party_flow?
      end

      condition(:duo_external_agents_enabled, scope: :subject) do
        @subject.project.root_ancestor.duo_external_agents_enabled
      end

      condition(:custom_flow, scope: :subject) do
        @subject.custom_flow?
      end

      condition(:custom_agent, scope: :subject) do
        @subject.custom_agent?
      end

      condition(:duo_custom_flows_enabled, scope: :subject) do
        @subject.project.root_ancestor.duo_custom_flows_enabled
      end

      condition(:duo_custom_agents_enabled, scope: :subject) do
        @subject.project.root_ancestor.duo_custom_agents_enabled
      end

      condition(:can_report_ai_catalog_item, scope: :user) do
        can?(:report_ai_catalog_item, :global)
      end

      condition(:can_admin_organization) do
        can?(:update_organization, @subject.organization)
      end

      # Scored above 16 so the cheaper `is_project_member & can_read_item_project` branch runs first
      # and members of the item project skip the expensive authorized root ancestors query.
      condition(:is_member_of_item_hierarchy, score: 20) do
        next false unless @user && @subject.project

        cached_user_authorized_root_ancestor_ids.include?(@subject.project.root_ancestor.id)
      end

      rule do
        public_item |
          (restricted_item & is_member_of_item_hierarchy & can_read_item_root_group) |
          (is_project_member & can_read_item_project) |
          can_admin_organization
      end.enable :read_ai_catalog_item, :report_ai_catalog_item

      rule { can_admin_ai_catalog_item | can_admin_organization }.policy do
        enable :admin_ai_catalog_item
        enable :delete_ai_catalog_item
        enable :restore_ai_catalog_item
      end

      rule { ~can_report_ai_catalog_item }.policy do
        prevent :report_ai_catalog_item
      end

      rule { ~ai_catalog_available_for_user }.policy do
        prevent :read_ai_catalog_item
        prevent :admin_ai_catalog_item
        prevent :delete_ai_catalog_item
        prevent :report_ai_catalog_item
        prevent :restore_ai_catalog_item
      end

      rule { deleted_item & ~can_admin_organization }.policy do
        prevent :admin_ai_catalog_item
        prevent :delete_ai_catalog_item
        prevent :restore_ai_catalog_item
      end

      rule { ~public_item & ~project_ai_catalog_available & ~can_admin_organization }.policy do
        prevent :read_ai_catalog_item
        prevent :report_ai_catalog_item
      end

      rule { ~project_ai_catalog_available & ~can_admin_organization }.policy do
        prevent :admin_ai_catalog_item
        prevent :delete_ai_catalog_item
        prevent :restore_ai_catalog_item
      end

      rule { flow & ~flows_available & ~can_admin_organization }.policy do
        prevent :admin_ai_catalog_item
        prevent :delete_ai_catalog_item
        prevent :restore_ai_catalog_item
      end

      rule { flow & ~public_item & ~flows_available & ~can_admin_organization }.policy do
        prevent :read_ai_catalog_item
        prevent :report_ai_catalog_item
      end

      rule { third_party_flow & ~third_party_flows_enabled & ~can_admin_organization }.policy do
        prevent :read_ai_catalog_item
        prevent :admin_ai_catalog_item
        prevent :delete_ai_catalog_item
        prevent :report_ai_catalog_item
        prevent :restore_ai_catalog_item
      end

      rule { third_party_flow & ~third_party_flows_available & ~can_admin_organization }.policy do
        prevent :admin_ai_catalog_item
        prevent :delete_ai_catalog_item
        prevent :restore_ai_catalog_item
      end

      rule { third_party_flow & ~public_item & ~third_party_flows_available & ~can_admin_organization }.policy do
        prevent :read_ai_catalog_item
        prevent :report_ai_catalog_item
      end

      rule { custom_flow & ~duo_custom_flows_enabled & ~can_admin_organization }.policy do
        prevent :admin_ai_catalog_item
        prevent :delete_ai_catalog_item
        prevent :restore_ai_catalog_item
      end

      rule { third_party_flow & ~duo_external_agents_enabled & ~can_admin_organization }.policy do
        prevent :admin_ai_catalog_item
        prevent :delete_ai_catalog_item
        prevent :restore_ai_catalog_item
      end

      rule { custom_agent & ~duo_custom_agents_enabled & ~can_admin_organization }.policy do
        prevent :admin_ai_catalog_item
        prevent :delete_ai_catalog_item
        prevent :restore_ai_catalog_item
      end

      private

      def cached_user_authorized_root_ancestor_ids
        Gitlab::SafeRequestStore.fetch([:cached_user_authorized_root_ancestor_ids, @user.id]) do
          Array(@user.authorized_root_ancestor_ids).to_set
        end
      end
    end
  end
end
