# frozen_string_literal: true

module EE::Gitlab::Analytics::CycleAnalytics::Aggregated::BaseQueryBuilder
  extend ::Gitlab::Utils::Override

  override :build
  def build
    query = filter_by_project_ids(super)
    query = filter_by_weight(query)
    query = filter_by_iteration(query)
    query = filter_by_epic(query)
    query = filter_by_my_reaction_emoji(query)
    filter_by_negated_params(query)
  end

  # rubocop: disable CodeReuse/ActiveRecord
  def build_sorted_query
    return super unless stage.parent.instance_of?(Group)

    ::Gitlab::Pagination::Keyset::InOperatorOptimization::QueryBuilder.new(
      scope: super.unscope(where: [:project_id, :group_id]), # unscoping the project_id and group_id queries because the in-operator optimization will apply these filters.
      array_scope: in_optimization_array_scope,
      array_mapping_scope: method(:in_optimization_array_mapping_scope)
    ).execute
  end

  private

  def filter_by_negated_params(query)
    return query unless params[:not]

    query = filter_by_negated_author_username(query)
    query = filter_by_negated_assignee_username(query)
    query = filter_by_negated_epic_id(query)
    query = filter_by_negated_iteration_id(query)
    query = filter_by_negated_label_name(query)
    query = filter_by_negated_milestone(query)
    query = filter_by_negated_my_reaction_emoji(query)
    filter_by_negated_weight(query)
  end

  def filter_by_negated_author_username(query)
    return query unless negated_filter_present?(:author_username)

    user = find_user(params[:not][:author_username])
    return query if user.blank?

    query.not_authored(user.id)
  end

  def filter_by_negated_assignee_username(query)
    return query unless negated_filter_present?(:assignee_username)

    Issuables::AssigneeFilter
      .new(params: { not: { assignee_username: params[:not][:assignee_username] } })
      .filter(query)
  end

  def filter_by_weight(query)
    return query unless issue_filter_present?(:weight)

    query.where(weight: params[:weight])
  end

  def filter_by_negated_weight(query)
    return query unless negated_issue_filter_present?(:weight)

    query.without_weight(params[:not][:weight])
  end

  def filter_by_iteration(query)
    return query unless issue_filter_present?(:iteration_id)

    query.where(sprint_id: params[:iteration_id])
  end

  def filter_by_negated_iteration_id(query)
    return query unless negated_issue_filter_present?(:iteration_id)

    query.without_sprint_id(params[:not][:iteration_id])
  end

  def filter_by_epic(query)
    return query unless issue_filter_present?(:epic_id)

    query.joins(:epic_issue).where(epic_issues: { epic_id: params[:epic_id] })
  end

  def filter_by_negated_epic_id(query)
    return query unless negated_issue_filter_present?(:epic_id)

    query.left_joins(:epic_issue).where('epic_issues.epic_id <> ? OR epic_issues.epic_id IS NULL', params[:not][:epic_id])
  end

  def filter_by_negated_label_name(query)
    return query unless negated_filter_present?(:label_name)

    ::Gitlab::Analytics::CycleAnalytics::Aggregated::LabelFilter.new(
      stage: stage,
      params: { not: { label_name: params[:not][:label_name] } },
      parent: root_ancestor
    ).filter(query)
  end

  def filter_by_negated_milestone(query)
    return query unless negated_filter_present?(:milestone_title)

    milestone = find_milestone(params[:not][:milestone_title])
    return query if milestone.nil?

    query.without_milestone_id(milestone.id)
  end

  def filter_by_my_reaction_emoji(query)
    return query unless params[:my_reaction_emoji]

    opts = {
      name: params[:my_reaction_emoji],
      base_class_name: stage.subject_class,
      awardable_id_column: stage_event_model.arel_table[stage_event_model.issuable_id_column]
    }

    query.awarded(params[:current_user], opts)
  end

  def filter_by_negated_my_reaction_emoji(query)
    return query unless negated_filter_present?(:my_reaction_emoji)

    opts = {
      name: params[:not][:my_reaction_emoji],
      base_class_name: stage.subject_class,
      awardable_id_column: stage_event_model.arel_table[stage_event_model.issuable_id_column]
    }

    query.not_awarded(params[:current_user], opts)
  end

  def issue_filter_present?(filter_name)
    stage.subject_class == ::Issue && params[filter_name]
  end

  def negated_issue_filter_present?(filter_name)
    stage.subject_class == ::Issue && params.dig(:not, filter_name)
  end

  def negated_filter_present?(filter_name)
    params[filter_name].blank? && params.dig(:not, filter_name).present?
  end

  def in_optimization_array_scope
    projects_filter_present? ? project_ids : stage.parent.self_and_descendant_ids.reselect(:id)
  end

  def in_optimization_array_mapping_scope(id_expression)
    issuable_id_column = projects_filter_present? ? :project_id : :group_id
    stage_event_model.where(stage_event_model.arel_table[issuable_id_column].eq(id_expression))
  end
  # rubocop: enable CodeReuse/ActiveRecord

  override :filter_by_stage_parent
  def filter_by_stage_parent(query)
    return super unless stage.parent.instance_of?(Group)

    query.by_group_id(stage.parent.self_and_descendant_ids)
  end

  def filter_by_project_ids(query)
    return query unless stage.parent.instance_of?(Group)
    return query unless projects_filter_present?

    query.by_project_id(project_ids)
  end

  def project_ids
    @project_ids ||= Project
      .id_in(params[:project_ids])
      .in_namespace(stage.parent.self_and_descendant_ids)
      .select(:id)
  end

  def projects_filter_present?
    Array(params[:project_ids]).any?
  end
end
