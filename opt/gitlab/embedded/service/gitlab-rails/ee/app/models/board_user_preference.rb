# frozen_string_literal: true

class BoardUserPreference < ApplicationRecord
  belongs_to :user, inverse_of: :board_preferences
  belongs_to :board, inverse_of: :user_preferences
  belongs_to :group
  belongs_to :project

  validates :user, presence: true
  validates :board, presence: true
  validates :user_id, uniqueness: { scope: :board_id, message: "should have only one board preference per user" }

  before_validation :ensure_group_or_project

  private

  def ensure_group_or_project
    self.group_id = board&.group_id
    self.project_id = board&.project_id
  end
end
