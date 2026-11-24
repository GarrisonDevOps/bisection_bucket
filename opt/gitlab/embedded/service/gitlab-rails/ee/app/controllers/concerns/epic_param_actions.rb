# frozen_string_literal: true

module EpicParamActions
  extend ActiveSupport::Concern

  def convert_epic_params
    rewritten_params = safe_params.to_h.except(:controller, :action, :namespace_id, :project_id, :id)

    # Translate epic_wildcard_id -> parent_wildcard_id
    rewritten_params[:parent_wildcard_id] = rewritten_params.delete(:epic_wildcard_id) if safe_params[:epic_wildcard_id]

    # Translate not: epic_id -> not: parent_id
    if safe_params.dig(:not, :epic_id)
      work_item_id = work_item_id_from_epic_id(safe_params[:not][:epic_id])
      rewritten_params[:not][:parent_id] = work_item_id if work_item_id
      rewritten_params[:not].delete(:epic_id)
    end

    # Translate epic_id -> parent_id
    if safe_params[:epic_id]
      if safe_params[:epic_id].to_s.downcase.in?([::IssuableFinder::Params::FILTER_NONE,
        ::IssuableFinder::Params::FILTER_ANY])
        rewritten_params[:parent_id] = rewritten_params.delete(:epic_id)
      else
        work_item_id = work_item_id_from_epic_id(safe_params[:epic_id])
        rewritten_params[:parent_id] = work_item_id if work_item_id
        rewritten_params.delete(:epic_id)
      end
    end

    rewritten_params
  end

  def has_epic_filter?
    safe_params[:epic_id] || safe_params[:epic_wildcard_id] ||
      (safe_params[:not].respond_to?(:key?) && safe_params.dig(:not, :epic_id))
  end

  def work_item_id_from_epic_id(epic_id)
    ::Epic.find_by_id(epic_id&.to_i)&.issue_id
  end
end
