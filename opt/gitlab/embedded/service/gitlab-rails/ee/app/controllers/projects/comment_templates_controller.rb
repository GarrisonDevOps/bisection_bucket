# frozen_string_literal: true

module Projects
  class CommentTemplatesController < Projects::ApplicationController
    feature_category :code_review_workflow

    before_action do
      render_404 unless Ability.allowed?(current_user, :read_saved_reply, @project)
    end
  end
end
