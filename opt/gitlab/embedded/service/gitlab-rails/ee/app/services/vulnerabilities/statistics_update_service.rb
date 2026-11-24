# frozen_string_literal: true

module Vulnerabilities
  class StatisticsUpdateService
    def self.update_for(vulnerability)
      new(vulnerability).execute
    end

    def initialize(vulnerability)
      self.vulnerability = vulnerability
    end

    def execute
      return if vulnerability.nil? || !stat_diff&.update_required?
      return if non_default_branch_vulnerability?

      Statistics::UpdateService.update_for(vulnerability)
      NamespaceStatistics::UpdateService.execute(vulnerability_to_diffs)
      Security::InventoryFilters::VulnerabilityStatisticsUpdateService.execute(project_to_diffs)
    end

    private

    attr_accessor :vulnerability

    def vulnerability_to_diffs
      return unless stat_diff&.update_required?

      formatted_traversal_ids = "{#{namespace.traversal_ids.join(', ')}}"

      diff_hash = {
        "namespace_id" => namespace.id,
        "traversal_ids" => formatted_traversal_ids
      }
      diff_hash.merge!(severity_changes)

      [diff_hash]
    end

    def project_to_diffs
      return unless stat_diff&.update_required?

      {
        vulnerability.project => severity_changes
      }
    end

    def severity_changes
      fill_in_zeros(stat_diff.changes)
    end

    def namespace
      @namespace ||= vulnerability.project.namespace
    end

    def stat_diff
      @stat_diff ||= vulnerability.stat_diff
    end

    def severity_levels
      ::Enums::Vulnerability.severity_levels.keys.map(&:to_s)
    end

    # Checks whether the vulnerability belongs to a non-default branch.
    # Matches the tracked context's name against the project's actual
    # default branch rather than relying on the `is_default` column,
    # which may have duplicate entries until the cleanup BBM is finalized.
    def non_default_branch_vulnerability?
      tracked_context = vulnerability.vulnerability_read&.tracked_context
      return false if tracked_context.blank?

      default_context = Security::ProjectTrackedContext.find_default_branch_context(vulnerability.project)
      default_context.nil? || tracked_context.id != default_context.id
    end

    def fill_in_zeros(changes)
      severity_levels.each do |key|
        changes[key] ||= 0
      end

      changes
    end
  end
end
