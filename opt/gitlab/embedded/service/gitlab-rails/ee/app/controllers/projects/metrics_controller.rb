# frozen_string_literal: true

module Projects
  class MetricsController < Projects::ApplicationController
    feature_category :observability

    before_action :authorize_read_observability!

    def index; end

    def show
      @metric_id = permitted_params[:id]
      @metric_type = permitted_params[:type]
    end

    private

    def permitted_params
      params.permit(:id, :type)
    end
  end
end
