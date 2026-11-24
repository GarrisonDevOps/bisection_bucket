# frozen_string_literal: true

module EE
  module DashboardController
    extend ActiveSupport::Concern

    prepended do
      before_action only: :work_items do
        push_frontend_feature_flag(:work_item_status_on_dashboard, current_user)
      end
    end
  end
end
