# frozen_string_literal: true

module Dashboard
  class OrbitController < Dashboard::ApplicationController
    feature_category :knowledge_graph
    urgency :low

    before_action :check_feature_flag!

    def show
      render
    end

    private

    def check_feature_flag!
      render_404 unless ::Analytics::KnowledgeGraph.enabled_for?(current_user)
    end
  end
end
