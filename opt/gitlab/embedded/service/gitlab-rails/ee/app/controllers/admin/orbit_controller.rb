# frozen_string_literal: true

module Admin
  class OrbitController < Admin::ApplicationController
    feature_category :knowledge_graph
    urgency :low

    before_action :set_application_setting

    def show
      render_404 unless can?(current_user, :read_knowledge_graph_setting)
    end

    def update
      return render_404 unless can?(current_user, :update_knowledge_graph_setting)

      result = ::ApplicationSettings::UpdateService
        .new(@application_setting, current_user, application_setting_params)
        .execute

      if result
        render json: @application_setting.slice(*::Analytics::KnowledgeGraph::Settings.all_settings.keys)
      else
        render json: { message: @application_setting.errors.full_messages.to_sentence },
          status: :unprocessable_entity
      end
    end

    private

    def set_application_setting
      @application_setting = ApplicationSetting.current_without_cache
    end

    def application_setting_params
      params.require(:application_setting).permit(*::Analytics::KnowledgeGraph::Settings.all_settings.keys)
    end
  end
end
