# frozen_string_literal: true

class EpicEntity < IssuableEntity
  include Gitlab::Utils::StrongMemoize

  expose :group_id

  expose :group_name do |epic|
    epic.group.name
  end
  expose :group_full_name do |epic|
    epic.group.full_name
  end
  expose :group_full_path do |epic|
    epic.group.full_path
  end

  expose :created_at do |epic|
    epic.work_item.created_at
  end

  expose :updated_at do |epic|
    epic.work_item.updated_at
  end

  expose :start_date do |epic|
    epic.work_item.start_date
  end

  expose :start_date_is_fixed?, as: :start_date_is_fixed do |epic|
    rollupable_dates(epic).fixed?
  end

  expose :start_date_fixed do |epic|
    rollupable_dates(epic).start_date
  end

  expose :start_date_from_milestones do |epic|
    rollupable_dates(epic).start_date
  end

  expose :end_date do |epic| # @deprecated
    epic.work_item.due_date
  end

  expose :end_date, as: :due_date do |epic|
    epic.work_item.due_date
  end

  expose :due_date_is_fixed?, as: :due_date_is_fixed do |epic|
    rollupable_dates(epic).fixed?
  end

  expose :due_date_fixed do |epic|
    rollupable_dates(epic).due_date
  end

  expose :due_date_from_milestones do |epic|
    rollupable_dates(epic).due_date
  end

  expose :state do |epic|
    epic.work_item.state
  end

  expose :lock_version do |epic|
    epic.work_item.lock_version
  end

  expose :confidential do |epic|
    epic.work_item.confidential
  end

  expose :color do |epic|
    epic.work_item.color&.color.to_s
  end

  expose :text_color do |epic|
    epic.work_item.color&.text_color.to_s
  end

  expose :web_url do |epic|
    group_epic_path(epic.group, epic)
  end
  expose :labels, using: LabelEntity do |epic|
    epic.work_item.labels
  end

  expose :current_user do
    expose :can_create_note do |epic|
      can?(request.current_user, :create_note, epic)
    end

    expose :can_create_confidential_note do |epic|
      can?(request.current_user, :mark_note_as_internal, epic)
    end

    expose :can_update do |epic|
      can?(request.current_user, :update_epic, epic)
    end
  end

  expose :create_note_path do |epic|
    group_epic_notes_path(epic.group, epic)
  end

  expose :preview_note_path do |epic|
    preview_markdown_path(epic.group, target_type: 'Epic', target_id: epic.iid)
  end

  expose :confidential_epics_docs_path, if: ->(epic) { epic.work_item.confidential? } do |epic|
    help_page_path('user/group/epics/manage_epics.md', anchor: 'make-an-epic-confidential')
  end

  private

  def rollupable_dates(epic)
    strong_memoize(:rollupable_dates) do
      epic.work_item.get_widget(:start_and_due_date)
    end
  end
end
