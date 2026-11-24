# frozen_string_literal: true

module Vulnerabilities
  class PartialScan < SecApplicationRecord
    include Ci::Partitionable::AssociationFinder

    self.table_name = 'vulnerability_partial_scans'

    enum :mode, {
      differential: 1
    }

    enum :scan_type, Security::Scan.scan_types

    belongs_to :project
    belongs_to :scan, class_name: 'Security::Scan'
    belongs_to :pipeline, class_name: 'Ci::Pipeline'
    partitionable_belongs_to_loader :pipeline

    validates :scan, presence: true
    validates :mode, presence: true
    validates :project, presence: true

    before_validation :set_attributes_from_scan

    scope :by_pipeline_ids, ->(pipeline_ids) { where(pipeline_id: pipeline_ids) }

    def self.distinct_scan_types
      # rubocop:disable Database/AvoidUsingPluckWithoutLimit -- This is limited by the number of scan types that exist
      select(:scan_type).distinct.pluck(:scan_type)
      # rubocop:enable Database/AvoidUsingPluckWithoutLimit
    end

    def set_attributes_from_scan
      # Since this happens before validation it is possible that there is no scan
      return unless scan

      self.project_id ||= scan.project_id
      self.pipeline_id ||= scan.pipeline_id
      self.scan_type ||= scan.scan_type
    end
  end
end
