# frozen_string_literal: true

class BoardAssignee < ApplicationRecord
  belongs_to :board
  belongs_to :assignee, class_name: 'User'
  belongs_to :group
  belongs_to :project

  validates :board, presence: true
  validates :assignee, presence: true
  validates :group, presence: true, unless: :project
  validates :project, presence: true, unless: :group
  validates :group, absence: {
    message: ->(_object, _data) { _("can't be specified if a project was already provided") }
  }, if: :project

  before_validation :ensure_group_or_project

  private

  def ensure_group_or_project
    self.group_id ||= board&.group_id
    self.project_id ||= board&.project_id
  end
end
