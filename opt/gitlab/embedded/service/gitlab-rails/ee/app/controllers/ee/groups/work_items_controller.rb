# frozen_string_literal: true

module EE
  module Groups
    module WorkItemsController
      extend ActiveSupport::Concern
      extend ::Gitlab::Utils::Override
      include ::Gitlab::Utils::StrongMemoize

      prepended do
        before_action :authorize_read_work_item!, only: [:description_diff, :delete_description_version]
        before_action :set_application_context!, only: [:show]

        before_action do
          push_frontend_feature_flag(:agent_presence_consolidation, group&.root_ancestor)
          push_frontend_feature_flag(:decision_log, group&.root_ancestor)
        end

        include DescriptionDiffActions
      end

      private

      def issuable
        ::WorkItem.find_by_namespace_and_iid!(group, params.permit(:iid)[:iid])
      end
      strong_memoize_attr :issuable

      def authorize_read_work_item!
        access_denied! unless can?(current_user, :read_work_item, issuable)
      end

      def set_application_context!
        ::Gitlab::ApplicationContext.push(ai_resource: issuable.try(:to_global_id))
      end
    end
  end
end
