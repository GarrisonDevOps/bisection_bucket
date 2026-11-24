# frozen_string_literal: true

class PathLock < ApplicationRecord
  belongs_to :project
  belongs_to :user

  validates :project, presence: true
  validates :user, presence: true
  validates :path, presence: true, uniqueness: { scope: :project_id }
  validate :path_unique_validation

  scope :for_paths, ->(paths) { where(path: paths) }
  scope :not_for_users, ->(user_ids) { where.not(user_id: user_ids) }
  scope :related_to_path, ->(path) do
    path = path.delete_suffix('/')
    segments = path.split('/')
    path_and_ancestors = Array.new(segments.size) { |i| segments[0..i].join('/') }

    for_paths(path_and_ancestors).or(where(arel_table[:path].matches("#{sanitize_sql_like(path)}/%", nil, true)))
  end

  def self.for_path(path)
    find_by(path: path)
  end

  def downstream?(path)
    self.path.start_with?(path) && !exact?(path)
  end

  def upstream?(path)
    path.start_with?(self.path) && !exact?(path)
  end

  def exact?(path)
    self.path == path
  end

  private

  # This takes into account upstream and downstream locks
  def path_unique_validation
    return unless path
    return unless project

    # We don't use `project.find_path_lock` as we want to avoid memoizing the finder
    # in project instance
    existed_lock = Gitlab::PathLocksFinder.new(project).find(path, downstream: true)

    return unless existed_lock

    if existed_lock.downstream?(path)
      errors.add(:path, _('is invalid because there is downstream lock'))
    elsif existed_lock.upstream?(path)
      errors.add(:path, _('is invalid because there is upstream lock'))
    end
  end
end
