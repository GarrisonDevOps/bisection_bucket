# frozen_string_literal: true

module Groups
  class CommentTemplatesController < Groups::ApplicationController
    feature_category :code_review_workflow

    before_action do
      render_404 unless Ability.allowed?(current_user, :read_saved_reply, @group)
    end
  end
end
