# frozen_string_literal: true

module Security
  class CustomSoftwareLicense < ApplicationRecord
    self.table_name = 'custom_software_licenses'

    belongs_to :project

    validates :name, presence: true, uniqueness: { scope: :project_id }, length: { maximum: 255 }

    scope :by_name, ->(names) { where(name: names) }
    scope :by_project, ->(project) { where(project: project) }

    def canonical_id
      name.downcase
    end
  end
end
