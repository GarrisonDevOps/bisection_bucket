# frozen_string_literal: true

class ResourceIterationEvent < ResourceTimeboxEvent
  belongs_to :iteration
  belongs_to :namespace
  belongs_to :triggered_by_work_item, class_name: 'WorkItem', foreign_key: 'triggered_by_id', optional: true,
    inverse_of: :resource_iteration_events

  validates :iteration, presence: true
  validates :namespace, presence: true

  before_validation :ensure_namespace_id

  scope :with_api_entity_associations, -> { preload(:iteration, :user) }
  scope :by_user, ->(user) { where(user_id: user) }

  scope :aliased_for_timebox_report, -> do
    select("'timebox' AS event_type", "id", "created_at", "iteration_id AS value", "action", "issue_id")
  end

  def synthetic_note_class
    IterationNote
  end

  private

  def ensure_namespace_id
    self.namespace_id = iteration&.group_id
  end
end
