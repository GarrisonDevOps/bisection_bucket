# frozen_string_literal: true

class EpicBaseEntity < Grape::Entity
  include RequestAwareEntity
  include EntityDateHelper

  expose :id

  expose :iid do |epic|
    epic.work_item.iid
  end

  expose :title do |epic|
    epic.work_item.title
  end

  expose :url do |epic|
    group_epic_path(epic.group, epic)
  end

  expose :group_id do |epic|
    epic.work_item.namespace_id
  end

  expose :human_readable_end_date, if: ->(epic, _) { epic.work_item.due_date.present? } do |epic|
    epic.work_item.due_date.to_fs(:medium)
  end

  expose :human_readable_timestamp, if: ->(epic, _) {
    epic.work_item.due_date.present? || epic.work_item.start_date.present?
  } do |epic|
    remaining_days_in_words(epic.work_item.due_date, epic.work_item.start_date)
  end
end
