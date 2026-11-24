# frozen_string_literal: true

class EpicIssue < ApplicationRecord
  include EpicTreeSorting
  include AfterCommitQueue
  include Epics::MetadataCacheUpdate

  validates :epic, :issue, presence: true
  validates :issue, uniqueness: true
  validates :work_item_parent_link, presence: true

  belongs_to :epic
  belongs_to :issue
  belongs_to :work_item, foreign_key: 'issue_id' # rubocop: disable Rails/InverseOf -- this relation is not present on WorkItem
  belongs_to :work_item_parent_link, class_name: 'WorkItems::ParentLink', inverse_of: :epic_issue
  belongs_to :namespace

  alias_attribute :parent_ids, :epic_id
  alias_method :parent, :epic
  alias_method :parent=, :epic=

  attr_accessor :work_item_syncing
  alias_method :work_item_syncing?, :work_item_syncing

  scope :in_epic, ->(epic_id) { where(epic_id: epic_id) }
  scope :for_issue, ->(issue_id) { where(issue_id: issue_id) }

  validate :validate_confidential_epic
  validate :check_existing_parent_link, unless: :work_item_syncing?
  validates_with Organizations::SameOrganizationValidator, left: :epic, right: :issue
  after_destroy :set_epic_id_to_update_cache
  after_save :set_epic_id_to_update_cache
  validate :validate_max_children

  def epic_tree_root?
    false
  end

  def self.epic_tree_node_query(node)
    selection = <<~SELECT_LIST
      id, relative_position, epic_id as parent_id, epic_id, '#{underscore}' as object_type
    SELECT_LIST

    select(selection).in_epic(node.parent_ids)
  end

  def self.find_or_initialize_from_parent_link(parent_link)
    return unless parent_link.work_item_parent.synced_epic

    epic_issue = EpicIssue.find_or_initialize_by(issue_id: parent_link.work_item.id)
    epic_issue.epic = parent_link.work_item_parent.synced_epic
    epic_issue.work_item_parent_link = parent_link

    epic_issue
  end

  def exportable_record?(user)
    Ability.allowed?(user, :read_epic, epic)
  end

  private

  def validate_confidential_epic
    return unless epic && issue

    if epic.confidential? && !issue.confidential?
      errors.add :issue, _('Cannot assign a confidential epic to a non-confidential issue. Make the issue confidential and try again')
    end
  end

  def set_epic_id_to_update_cache
    register_epic_id_for_cache_update(epic_id)

    register_epic_id_for_cache_update(epic_id_previously_was) if epic_id_previously_changed? && epic_id_previously_was
  end

  def check_existing_parent_link
    return unless epic && issue

    existing_parent_epic = WorkItems::ParentLink.for_children(issue).first
    return unless existing_parent_epic && existing_parent_epic.work_item_parent_id != epic.issue_id

    errors.add(:issue, _('already assigned to an epic'))
  end

  def validate_max_children
    return unless epic && issue

    if epic.max_children_count_achieved?
      errors.add(:issue, _('cannot be linked to the epic. This epic already has maximum number of child issues & epics.'))
    end
  end
end
