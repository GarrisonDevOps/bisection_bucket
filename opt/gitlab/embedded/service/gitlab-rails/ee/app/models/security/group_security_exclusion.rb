# frozen_string_literal: true

module Security
  class GroupSecurityExclusion < ::SecApplicationRecord
    self.inheritance_column = :_type_disabled

    belongs_to :group

    enum :scanner, { secret_push_protection: 0 }
    enum :type, { path: 0, regex_pattern: 1, raw_value: 2, rule: 3 }

    validates :scanner, :type, :value, :group, presence: true
    validates :active, inclusion: { in: [true, false] }
    validates :value, :description, length: { maximum: 255 }
  end
end
