# frozen_string_literal: true

module CycleAnalyticsParams
  extend ActiveSupport::Concern

  def cycle_analytics_project_params
    cycle_analytics_project_filters.presence || {}
  end

  def cycle_analytics_group_params
    cycle_analytics_group_filters.presence || {}
  end

  def options(params)
    @options ||= {}.tap do |opts|
      opts[:current_user] = current_user
      opts[:projects] = params[:project_ids] if params[:project_ids]
      opts[:from] = params[:from] || start_date(params)
      opts[:to] = params[:to] if params[:to]
      opts[:end_event_filter] = params[:end_event_filter] if params[:end_event_filter]
      if params[:use_aggregated_data_collector]
        opts[:use_aggregated_data_collector] = params[:use_aggregated_data_collector]
      end

      opts.merge!(params.slice(*::Gitlab::Analytics::CycleAnalytics::RequestParams::FINDER_PARAM_NAMES))
      opts.merge!(date_range(params))
    end
  end

  private

  def cycle_analytics_project_filters
    params.permit(cycle_analytics: [:start_date, :created_after, :created_before, :branch_name])[:cycle_analytics]
  end

  def cycle_analytics_group_filters
    params.permit(:group_id, :start_date, :created_after, :created_before, project_ids: [])
  end

  def start_date(params)
    case params[:start_date]
    when '7'
      7.days.ago
    when '30'
      30.days.ago
    else
      90.days.ago
    end
  end

  def date_range(params)
    {}.tap do |date_range_params|
      date_range_params[:from] = to_utc_time(params[:created_after]).beginning_of_day if params[:created_after]
      date_range_params[:to] = to_utc_time(params[:created_before]).end_of_day if params[:created_before]
    end.compact
  end

  def to_utc_time(field)
    date = field.is_a?(Date) || field.is_a?(Time) ? field : Date.parse(field)
    date.to_time.utc
  end

  def permitted_cycle_analytics_params
    params.permit(*::Gitlab::Analytics::CycleAnalytics::RequestParams::STRONG_PARAMS_DEFINITION)
  end

  def all_cycle_analytics_params
    permitted_cycle_analytics_params.merge(current_user: current_user, namespace: namespace)
  end

  def request_params
    @request_params ||= ::Gitlab::Analytics::CycleAnalytics::RequestParams.new(all_cycle_analytics_params)
  end

  def validate_params
    if request_params.invalid?
      render(
        json: { message: 'Invalid parameters', errors: request_params.errors },
        status: :unprocessable_entity
      )
    end
  end

  def check_project_value_stream_analytics_rate_limit!
    scope = current_user ? { user: current_user } : { ip: request.ip }

    check_rate_limit!(:project_value_stream_analytics, scope: scope.merge(project: project))
  end

  # The legacy project endpoints read their dates from the nested `cycle_analytics` params,
  # so `validate_params` (which reads the top-level params) does not apply to them.
  def validate_project_date_range
    date_range = options(cycle_analytics_project_params)
    from = date_range[:from].beginning_of_day
    to = (date_range[:to] || Time.current.utc).beginning_of_day

    return render_project_date_range_error(:created_before, I18n.t('errors.messages.invalid')) if to < from
    return if to - from <= ::Gitlab::Analytics::CycleAnalytics::RequestParams::MAX_RANGE_DAYS

    render_project_date_range_error(:created_after, s_('CycleAnalytics|The given date range is larger than 180 days'))
  rescue ArgumentError
    render_project_date_range_error(invalid_project_date_param, I18n.t('errors.messages.invalid'))
  end

  def invalid_project_date_param
    %i[created_after created_before].find do |name|
      value = cycle_analytics_project_params[name]
      next false if value.nil?

      Date.parse(value)
      false
    rescue ArgumentError
      true
    end
  end

  def render_project_date_range_error(field, message)
    render(
      json: { message: 'Invalid parameters', errors: { field => [message] } },
      status: :unprocessable_entity
    )
  end
end
