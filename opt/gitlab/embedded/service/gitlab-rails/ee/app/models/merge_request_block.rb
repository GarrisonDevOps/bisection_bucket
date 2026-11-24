# frozen_string_literal: true

class MergeRequestBlock < ApplicationRecord
  belongs_to :blocking_merge_request, class_name: 'MergeRequest'
  belongs_to :blocked_merge_request, class_name: 'MergeRequest'
  belongs_to :project

  validates_presence_of :blocking_merge_request
  validates_presence_of :blocked_merge_request
  validates_uniqueness_of :blocked_merge_request, scope: :blocking_merge_request

  validate :check_block_constraints
  validate :check_organization_isolation

  MAX_BLOCKS_COUNT = 10
  MAX_BLOCKED_BY_COUNT = 10

  scope :with_blocking_mr_ids, ->(ids) do
    where(blocking_merge_request_id: ids).includes(:blocking_merge_request)
  end

  def self.for_merge_requests(mr1, mr2)
    where(blocking_merge_request: mr1, blocked_merge_request: mr2)
      .or(where(blocking_merge_request: mr2, blocked_merge_request: mr1))
      .first
  end

  private

  def check_block_constraints
    return unless blocking_merge_request && blocked_merge_request

    errors.add(:base, _('This block is self-referential')) if
      blocking_merge_request == blocked_merge_request

    if blocks_count >= MAX_BLOCKS_COUNT
      msg = _('Merge request blocks the maximum number of merge requests (%{max_count})')
      errors.add(:base, format(msg, max_count: MAX_BLOCKS_COUNT))
    end

    return unless blocked_by_count >= MAX_BLOCKED_BY_COUNT

    msg = _('Merge request is blocked by the maximum number of merge requests (%{max_count})')
    errors.add(:base, format(msg, max_count: MAX_BLOCKED_BY_COUNT))
  end

  def check_organization_isolation
    return unless blocking_merge_request && blocked_merge_request

    return if blocking_merge_request.project.organization_id == blocked_merge_request.project.organization_id

    blocked_org = blocked_merge_request.project.organization
    return unless blocked_org.isolated?

    errors.add(:base, _('The blocking merge request must be in the same organization'))
  end

  def blocked_by_count
    blocking_merge_request.blocks_as_blockee.count
  end

  def blocks_count
    blocked_merge_request.blocks_as_blocker.count
  end
end
