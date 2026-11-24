# frozen_string_literal: true

module Security
  # Per-group summary of DependencyFirewallPreventedPackage for the 7 and 30 day dashboard windows,
  # recomputed periodically so group reads do not aggregate across every project at query time.
  class DependencyFirewallNamespacePreventedStat < ApplicationRecord
    self.table_name = 'dependency_firewall_namespace_prevented_stats'

    WINDOWS = [7, 30].freeze
    SEVERITIES = %w[critical high medium low info unknown].freeze

    belongs_to :namespace, optional: false

    validates :window_days, inclusion: { in: WINDOWS }

    def self.find_for_namespace_window(namespace_id, days)
      find_by(namespace_id: namespace_id, window_days: days)
    end

    def self.group_traversal_ids_for_projects(project_ids)
      Project.where(id: project_ids)
        .joins(:namespace)
        .where(namespaces: { type: 'Group' })
        .limit(project_ids.size)
        .pluck('namespaces.traversal_ids')
    end

    def self.group_traversal_ids_for_namespaces(namespace_ids)
      Group.id_in(namespace_ids).limit(namespace_ids.size).pluck(:traversal_ids)
    end

    def to_counts
      {
        vulnerabilities: { prevented: vulnerabilities_prevented, by_severity: by_severity },
        malicious: { prevented: malicious_packages_prevented, warned_only: malicious_packages_warned_only },
        license: { prevented: license_risks_prevented, warned_only: license_risks_warned_only }
      }
    end

    private

    def by_severity
      SEVERITIES.index_with { |severity| self["severity_#{severity}"] }.select { |_, count| count > 0 }
    end
  end
end
