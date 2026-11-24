# frozen_string_literal: true

module Activation
  class MetricsFinder
    attr_reader :user, :params

    def initialize(user:, params: {})
      @user = user
      @params = params
    end

    def execute
      metrics = ::Activation::Metric.for_user(user)
      metrics = by_namespace(metrics)
      by_metric(metrics)
    end

    private

    def by_namespace(metrics)
      return metrics unless params[:namespace].present?

      metrics.for_namespace(params[:namespace])
    end

    def by_metric(metrics)
      return metrics unless params[:metric].present?

      metrics.by_metric(params[:metric])
    end
  end
end
