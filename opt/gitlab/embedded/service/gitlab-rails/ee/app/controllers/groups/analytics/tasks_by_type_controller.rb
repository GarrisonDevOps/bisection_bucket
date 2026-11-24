# frozen_string_literal: true

class Groups::Analytics::TasksByTypeController < Groups::Analytics::ApplicationController
  before_action -> { check_feature_availability!(:type_of_work_analytics) }
  before_action -> { authorize_view_by_action!(:view_type_of_work_charts) }
  before_action :check_tasks_by_type_rate_limit!
  before_action :validate_label_name, only: :show
  before_action :prepare_date_range

  def show
    render json: Analytics::TasksByTypeLabelEntity.represent(counts_by_labels)
  end

  def top_labels
    render json: LabelEntity.represent(tasks_by_type.top_labels)
  end

  private

  def counts_by_labels
    tasks_by_type.counts_by_labels
  end

  def tasks_by_type
    Gitlab::Analytics::TypeOfWork::TasksByType.new(group: @group, current_user: current_user, params: {
      subject: tasks_by_type_params[:subject],
      label_names: Array(tasks_by_type_params[:label_names]),
      project_ids: Array(tasks_by_type_params[:project_ids]),
      created_after: @created_after.to_time.utc.beginning_of_day,
      created_before: @created_before.to_time.utc.end_of_day,
      author_username: tasks_by_type_params[:author_username],
      assignee_username: tasks_by_type_params[:assignee_username],
      milestone_id: tasks_by_type_params[:milestone_id]
    })
  end

  def tasks_by_type_params
    params.permit(
      :subject,
      :author_username,
      :assignee_username,
      :milestone_id,
      :created_after,
      :created_before,
      label_names: [],
      project_ids: []
    )
  end

  def check_tasks_by_type_rate_limit!
    return unless Feature.enabled?(:tasks_by_type_rate_limit, group.root_ancestor)

    check_rate_limit!(:tasks_by_type, scope: { user: current_user, group: group })
  end

  def validate_label_name
    respond_422 if Array(tasks_by_type_params[:label_names]).empty?
  end

  def prepare_date_range
    @created_after = parse_date(tasks_by_type_params[:created_after])
    return respond_422 unless @created_after

    @created_before = parse_date(tasks_by_type_params[:created_before]) || Date.today

    return respond_422 if @created_after > @created_before

    respond_422 if @created_after < @created_before - Gitlab::Analytics::CycleAnalytics::RequestParams::MAX_RANGE_DAYS
  end

  def parse_date(value)
    return unless value

    Date.parse(value)
  rescue ArgumentError
  end
end
