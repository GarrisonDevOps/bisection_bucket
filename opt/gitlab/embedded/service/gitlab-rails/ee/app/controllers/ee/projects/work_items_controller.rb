# frozen_string_literal: true

module EE
  module Projects
    module WorkItemsController
      extend ActiveSupport::Concern

      prepended do
        include ::Observability::ObservabilityIssuesHelper

        before_action only: [:index, :new, :show] do
          push_licensed_feature(:generate_description, project) if can?(current_user, :generate_description, project)
        end

        before_action do
          push_force_frontend_feature_flag(:okrs_mvc, !!project&.okrs_mvc_feature_flag_enabled?)
          push_frontend_feature_flag(:agent_presence_consolidation, project&.root_ancestor)
          push_frontend_feature_flag(:decision_log, project&.root_ancestor)
        end

        before_action only: :new do
          # rubocop: disable Rails/StrongParams -- legacy code
          if can?(current_user, :read_observability, project)
            @observability_values = gather_observability_values(params)
          end
          # rubocop: enable Rails/StrongParams
        end

        before_action :set_application_context!, only: [:show]
      end

      private

      def set_application_context!
        ::Gitlab::ApplicationContext.push(ai_resource: issuable.try(:to_global_id))
      end
    end
  end
end
