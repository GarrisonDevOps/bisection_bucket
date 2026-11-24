# frozen_string_literal: true

class EpicPresenter < Gitlab::View::Presenter::Delegated
  include GitlabRoutingHelper
  include EntityDateHelper
  include Gitlab::Utils::StrongMemoize

  delegator_override_with Gitlab::Utils::StrongMemoize
  presents ::Epic, as: :epic

  def group_epic_path
    epic_view.web_edit_url
  end

  def group_epic_url
    epic_view.web_url
  end

  def epic_reference(full: false)
    if full
      epic_view.to_reference(full: true)
    else
      epic_view.to_reference(epic_view.parent&.group || epic_view.group)
    end
  end

  delegator_override :subscribed?
  def subscribed?
    return false if current_user.blank?

    epic_view.subscribed?(current_user)
  end

  # With the new WorkItem structure the logic for the "inherited"/"fixed" dates changed
  # To ensure we're using the same values on the new UI/APIs and on the legacy (like Roadmaps)
  # we overwrite the *_date* methods to use the logic from WorkItems::StartAndDueDate
  # We also read other attributes from work_item to ensure consistency
  delegator_override :start_date,
    :start_date_fixed,
    :start_date_is_fixed,
    :start_date_is_fixed?,
    :start_date_from_milestones,
    :due_date,
    :due_date_fixed,
    :due_date_is_fixed,
    :due_date_is_fixed?,
    :due_date_from_milestones,
    :created_at,
    :updated_at,
    :state,
    :lock_version,
    :labels,
    :author,
    :confidential,
    :confidential?,
    :color,
    :text_color,
    :title,
    :description

  def start_date
    epic_view.start_date
  end
  alias_method :start_date_fixed, :start_date

  def due_date
    epic_view.due_date
  end
  alias_method :due_date_fixed, :due_date

  def start_date_is_fixed?
    epic_view.start_date_is_fixed?
  end
  alias_method :due_date_is_fixed?, :start_date_is_fixed?

  def work_item_id
    epic_view.work_item_id
  end

  def created_at
    epic_view.created_at
  end

  def state
    epic_view.state
  end

  def lock_version
    epic_view.lock_version
  end

  def labels
    epic_view.labels
  end

  def author
    epic_view.author
  end

  def updated_at
    epic_view.updated_at
  end

  def confidential
    epic_view.confidential
  end
  alias_method :confidential?, :confidential

  def color
    epic_view.color
  end

  def text_color
    epic_view.text_color
  end

  def title
    epic_view.title
  end

  def description
    epic_view.description
  end

  def start_date_from_milestones
    epic_view.start_date_from_milestones
  end

  def due_date_from_milestones
    epic_view.due_date_from_milestones
  end

  private

  def epic_view
    @epic_view ||= ::WorkItems::LegacyEpics::WorkItemAsEpic.new(work_item)
  end
  strong_memoize_attr :epic_view

  def work_item
    epic.work_item
  end
  strong_memoize_attr :work_item
end
