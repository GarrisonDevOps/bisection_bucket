# frozen_string_literal: true

module Security
  # Pre-aggregated hourly counts of dependency firewall enforcement activity, per triggering
  # project and (when one matched) per rule. Tracks blocked, warned and allowed outcomes.
  # "allowed" rows always have a NULL rule_id (no rule matched) and power the "Total Triggers"
  # summary; blocked/warned rows carry the matched rule for the per-rule Activity column.
  # Buckets are hour-granular (stat_time = start of the hour, UTC), so the dashboard can sum
  # over rolling sub-day windows (e.g. last 6h/12h/24h) as well as week/month.
  class DependencyFirewallActivityStat < ApplicationRecord
    include ::Analytics::HasWriteBuffer

    self.table_name = 'dependency_firewall_activity_stats'
    self.write_buffer_options = { class: ::Security::DependencyFirewall::ActivityStatWriteBuffer }

    enum :outcome, { blocked: 0, warned: 1, allowed: 2 }, prefix: true

    belongs_to :dependency_firewall_policy_rule,
      class_name: 'Security::DependencyFirewallPolicyRule', optional: true
    belongs_to :project, optional: false

    validates :stat_time, presence: true
    validates :outcome, presence: true
    validates :count, presence: true, numericality: { greater_than_or_equal_to: 0 }
    validate :allowed_outcome_has_no_rule

    scope :for_rules, ->(rule_ids) { where(dependency_firewall_policy_rule_id: rule_ids) }
    scope :in_time_range, ->(range) { where(stat_time: range) }

    # A bare id list uses IN; a project relation (e.g. a group's `all_projects`) uses a correlated
    # WHERE EXISTS instead of IN (<subquery>), which performs better at scale per the SQL guidelines
    # (https://docs.gitlab.com/development/sql/#use-where-exists-instead-of-where-in).
    scope :for_projects, ->(projects) {
      if projects.is_a?(ActiveRecord::Relation)
        where(projects.where(Project.arel_table[:id].eq(arel_table[:project_id])).select(1).arel.exists)
      else
        where(project_id: projects)
      end
    }

    def self.increment!(project_id:, outcome:, rule_id: nil, time: Time.current)
      # A bucket violating the allowed-has-no-rule CHECK would fail every flush run; fail this call instead.
      raise ArgumentError, 'allowed outcome cannot carry a rule_id' if outcome.to_s == 'allowed' && rule_id

      write_buffer.add(
        dependency_firewall_policy_rule_id: rule_id,
        project_id: project_id,
        stat_time: time.utc.beginning_of_hour,
        outcome: outcomes.fetch(outcome.to_s)
      )
    end

    def self.bulk_increment!(rows)
      return if rows.empty?

      upsert_all(
        rows,
        unique_by: :i_dep_fw_activity_stats_unique,
        on_duplicate: Arel.sql(
          'count = dependency_firewall_activity_stats.count + excluded.count, updated_at = now()'
        )
      )
    end

    # Per-rule blocked/warned totals over the given projects and time range. Returns
    # { rule_id => { blocked: Integer, warned: Integer } } per requested rule id. "allowed" is
    # never per-rule (allowed rows always carry a NULL rule_id, enforced by the table's CHECK
    # constraint), so allowed activity is counted group-wide via .outcome_totals instead.
    def self.activity_counts_by_rule(rule_ids:, project_ids:, time_range:)
      totals = for_rules(rule_ids).for_projects(project_ids).in_time_range(time_range)
        .group(:dependency_firewall_policy_rule_id, :outcome).sum(:count)

      rule_ids.index_with do |rule_id|
        { blocked: totals[[rule_id, 'blocked']].to_i, warned: totals[[rule_id, 'warned']].to_i }
      end
    end

    # Group-level totals per outcome across all projects + rules (including NULL-rule allowed
    # rows). Powers the "Actions this week" / "Total Triggers" summary cards.
    def self.outcome_totals(project_ids:, time_range:)
      totals = for_projects(project_ids).in_time_range(time_range).group(:outcome).sum(:count)

      { blocked: totals['blocked'].to_i, warned: totals['warned'].to_i, allowed: totals['allowed'].to_i }
    end

    private

    # Model mirror of the check_allowed_outcome_has_null_rule DB constraint (bulk_increment!
    # relies on the DB; increment! raises at the boundary).
    def allowed_outcome_has_no_rule
      return unless outcome_allowed? && dependency_firewall_policy_rule_id.present?

      errors.add(:dependency_firewall_policy_rule_id, 'must be blank when outcome is allowed')
    end
  end
end
