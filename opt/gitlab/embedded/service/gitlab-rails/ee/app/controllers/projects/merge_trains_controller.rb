# frozen_string_literal: true

module Projects
  class MergeTrainsController < Projects::ApplicationController
    feature_category :merge_trains
    before_action :authorize_read_merge_train!
    before_action :authorize!

    def index; end

    private

    def authorize!
      render_404 unless current_user && merge_trains_available?
    end

    def merge_trains_available?
      project.licensed_feature_available?(:merge_trains)
    end
  end
end
