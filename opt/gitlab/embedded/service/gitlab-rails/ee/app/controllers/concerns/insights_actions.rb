# frozen_string_literal: true

module InsightsActions
  extend ActiveSupport::Concern

  included do
    before_action :check_insights_available!
    before_action :check_insights_query_rate_limit!, only: [:query]
    before_action :validate_params, only: [:query]

    helper_method :insights_notice_text

    rescue_from Gitlab::Insights::Validators::ParamsValidator::ParamsValidatorError,
      Gitlab::Insights::Finders::IssuableFinder::IssuableFinderError,
      Gitlab::Insights::Executors::DoraExecutor::DoraExecutorError,
      Gitlab::Insights::Reducers::BaseReducer::BaseReducerError, with: :render_insights_chart_error

    rescue_from ActiveRecord::QueryCanceled do |exception|
      raise exception unless request.format.json?

      log_exception(exception)

      message = s_('ContributionAnalytics|There is too much data to calculate. ' \
                  'Try lowering the period_limit setting in the insights configuration file.')
      render json: { message: message }, status: :unprocessable_entity
    end
  end

  def show
    respond_to do |format|
      format.html
      format.json do
        render json: filtered_config
      end
    end
  end

  def query
    respond_to do |format|
      format.json do
        render json: ::Gitlab::Insights::Loader.new(
          insights_entity: insights_entity,
          current_user: current_user,
          params: insights_params
        ).execute
      end
    end
  end

  def insights_notice_text
    invalid_insights_config_notice unless insights_entity.insights_config_valid?
  end

  private

  def check_insights_available!
    render_404 unless insights_entity.insights_available?
  end

  def check_insights_query_rate_limit!
    caller_scope = current_user ? { user: current_user } : { ip: request.ip }
    namespace = insights_entity.is_a?(Project) ? insights_entity.project_namespace : insights_entity

    # Render JSON so the chart shows the message instead of a generic error.
    check_rate_limit!(:insights_query, scope: caller_scope.merge(namespace: namespace)) do
      render json: { message: Gitlab::ApplicationRateLimiter.throttled_error_message }, status: :too_many_requests
    end
  end

  def validate_params
    Gitlab::Insights::Validators::ParamsValidator.new(insights_params, insights_entity: insights_entity).validate!
  end

  # `query` and `projects` are config-driven nested structures (a chart query
  # definition and a project filter), so they are permitted as arbitrary hashes.
  def insights_params
    params.permit(:type, query: {}, projects: {})
  end

  def config_data
    insights_entity.insights_config
  end

  def filtered_config
    Gitlab::Insights::ConfigurationFilter.new(
      config: config_data,
      user: current_user,
      insights_entity: insights_entity
    ).execute
  end

  def invalid_insights_config_notice
    s_('Insights|The Insights configuration file (.gitlab/insights.yml) is not valid. ' \
       'Please correct it to load your insights.')
  end

  def render_insights_chart_error(exception)
    render json: { message: exception.message }, status: :unprocessable_entity
  end
end
