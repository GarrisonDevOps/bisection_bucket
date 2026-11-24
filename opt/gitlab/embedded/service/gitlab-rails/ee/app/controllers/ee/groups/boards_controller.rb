# frozen_string_literal: true

module EE
  module Groups
    module BoardsController
      extend ActiveSupport::Concern

      prepended do
        before_action do
          push_force_frontend_feature_flag(:work_item_epics, group.allowed_work_item_type?(:epic))
          push_frontend_feature_flag(:duo_agent_sessions_on_board, group.root_ancestor)
        end
      end
    end
  end
end
