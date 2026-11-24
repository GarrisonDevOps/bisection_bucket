# frozen_string_literal: true

module Vulnerabilities
  class FlipGuard < ::SecApplicationRecord
    include BulkInsertSafe

    self.table_name = 'vulnerability_flip_guards'
    self.primary_key = :vulnerability_finding_id

    belongs_to :finding, class_name: 'Vulnerabilities::Finding', foreign_key: 'vulnerability_finding_id',
      inverse_of: :flip_guard
    belongs_to :project

    validates :finding, presence: true, uniqueness: true
    validates :project, presence: true
    validates :first_automatic_transition_at, presence: true
    validates :last_automatic_transition_at, presence: true
  end
end
