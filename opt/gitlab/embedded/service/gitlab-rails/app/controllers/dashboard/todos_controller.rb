# frozen_string_literal: true

class Dashboard::TodosController < Dashboard::ApplicationController
  include Gitlab::InternalEventsTracking

  feature_category :notifications
  urgency :low

  before_action do
    push_frontend_feature_flag(:review_decision_todo_actions, current_user)
  end

  def index
    track_internal_event(
      'view_todo_list',
      user: current_user
    )
  end
end
