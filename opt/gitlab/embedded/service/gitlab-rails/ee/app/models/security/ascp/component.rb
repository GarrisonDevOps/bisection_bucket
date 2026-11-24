# frozen_string_literal: true

module Security
  module Ascp
    class Component < ::SecApplicationRecord
      include StripAttribute

      self.table_name = 'ascp_components'

      belongs_to :project, inverse_of: :security_ascp_components
      belongs_to :scan, class_name: 'Security::Ascp::Scan', inverse_of: :components

      has_one :security_context, class_name: 'Security::Ascp::SecurityContext', inverse_of: :component
      has_many :vulnerability_finding_ascp_component_links,
        class_name: 'Vulnerabilities::AscpComponentLink',
        inverse_of: :ascp_component
      has_many :vulnerability_findings,
        through: :vulnerability_finding_ascp_component_links,
        source: :vulnerability_finding
      has_many :dependencies, class_name: 'Security::Ascp::ComponentDependency', inverse_of: :component
      has_many :dependency_components, through: :dependencies, source: :dependency
      has_many :dependents, class_name: 'Security::Ascp::ComponentDependency',
        foreign_key: :dependency_id, inverse_of: :dependency

      strip_attributes! :title, :sub_directory, :description, :expected_user_behavior

      validates :project, :scan, :title, :sub_directory, presence: true
      validates :sub_directory, uniqueness: { scope: [:project_id, :scan_id] }
      validates :title, length: { maximum: 255 }
      validates :sub_directory, length: { maximum: 1024 }
      validates :description, length: { maximum: 4096 }
      validates :expected_user_behavior, length: { maximum: 4096 }

      scope :by_project, ->(project_id) { where(project_id: project_id) }
      scope :by_title, ->(title) { where(arel_table[:title].matches("%#{sanitize_sql_like(title)}%")) }
      scope :by_sub_directory, ->(sub_directory) { where(sub_directory: sub_directory) }
      scope :at_scan, ->(scan_id) { where(scan_id: scan_id) }
      scope :ordered, -> { order(id: :desc) }

      def self.pluck_id_and_sub_directory(limit = MAX_PLUCK)
        limit(limit).pluck(:id, :sub_directory)
      end

      def self.find_for_project(id, project_id)
        by_project(project_id).find_by(id: id)
      end
    end
  end
end
