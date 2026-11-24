# frozen_string_literal: true

module Security
  # Distinct-entity ledger: one row per (project, rule type, purl), unlike the event-counting
  # DependencyFirewallActivityStat. Dashboard windows always end at now, so last_blocked_at >= from
  # answers "prevented in the window" with an index scan.
  class DependencyFirewallPreventedPackage < ApplicationRecord
    include ::Analytics::HasWriteBuffer

    self.table_name = 'dependency_firewall_prevented_packages'
    self.write_buffer_options = { class: ::Security::DependencyFirewall::PreventedPackageWriteBuffer }

    # Severity integers rank monotonically (info 1 .. critical 7), which is what lets the
    # flush upsert keep the max via GREATEST.
    enum :severity, ::Enums::Vulnerability.severity_levels, prefix: true
    enum :rule_type, ::Security::DependencyFirewallPolicyRule.types, prefix: true

    belongs_to :project, optional: false

    validates :identifier, presence: true, length: { maximum: 512 }
    validates :rule_type, presence: true
    validates :first_seen_at, presence: true
    validate :severity_only_for_vulnerability_rules
    validate :at_least_one_prevention_timestamp

    # Distinct from other ArgumentErrors so the flush worker can discard just these rows, e.g. a
    # rule type buffered by a newer node during a mixed-version deploy.
    InvalidEnumValueError = Class.new(ArgumentError)

    # Merge, never overwrite: replays and out-of-order flushes can only advance a row.
    # Byte-wise purl comparison, as in Sbom::Occurrence: a faster sort, same results.
    IDENTIFIER_C_COLLATION = Arel.sql('"dependency_firewall_prevented_packages"."identifier" COLLATE "C"').freeze

    ON_DUPLICATE_MERGE = Arel.sql(
      <<~SQL.squish
        first_seen_at = LEAST(dependency_firewall_prevented_packages.first_seen_at, excluded.first_seen_at),
        last_blocked_at = GREATEST(dependency_firewall_prevented_packages.last_blocked_at, excluded.last_blocked_at),
        last_warned_at = GREATEST(dependency_firewall_prevented_packages.last_warned_at, excluded.last_warned_at),
        severity = GREATEST(dependency_firewall_prevented_packages.severity, excluded.severity),
        updated_at = now()
      SQL
    ).freeze

    WINDOW_FLAG_KEYS = %i[
      card identifier blocked_7 warned_only_7 max_severity_7 blocked_30 warned_only_30 max_severity_30
    ].freeze

    scope :for_rule_types, ->(rule_types) { where(rule_type: rule_types) }
    scope :blocked_since, ->(from) { where(arel_table[:last_blocked_at].gteq(from)) }
    scope :warned_only_since, ->(from) {
      where(arel_table[:last_warned_at].gteq(from))
        .where(arel_table[:last_blocked_at].eq(nil).or(arel_table[:last_blocked_at].lt(from)))
    }

    # Id lists use IN; project relations (a group's all_projects) become a correlated EXISTS so the
    # hierarchy resolves inside PostgreSQL instead of being serialized into the statement.
    scope :for_projects, ->(projects) {
      if projects.is_a?(ActiveRecord::Relation)
        where_exists(projects.where(Project.arel_table[:id].eq(arel_table[:project_id])))
      else
        where(project_id: projects)
      end
    }

    def self.distinct_blocked_count(projects:, rule_types:, from:)
      for_projects(projects).for_rule_types(rule_types).blocked_since(from).distinct.count(IDENTIFIER_C_COLLATION)
    end

    def self.distinct_warned_only_count(projects:, rule_types:, from:)
      for_projects(projects).for_rule_types(rule_types).warned_only_since(from).distinct.count(IDENTIFIER_C_COLLATION)
    end

    # { severity => purl count }, each purl once at its max severity (nil: never had one).
    def self.blocked_count_by_max_severity(projects:, rule_types:, from:)
      from(
        for_projects(projects).for_rule_types(rule_types).blocked_since(from)
          .group(IDENTIFIER_C_COLLATION).select('MAX(severity) AS max_severity'),
        :max_severities
      ).group('max_severity').count
    end

    def self.window_flags(project_ids:, from_7:, from_30:)
      card = window_flag_card

      # rubocop:disable Database/AvoidUsingPluckWithoutLimit -- one row per distinct (card, purl) in the window
      where(project_id: project_ids)
        .where(arel_table[:last_blocked_at].gteq(from_30).or(arel_table[:last_warned_at].gteq(from_30)))
        .group(Arel.sql(card), IDENTIFIER_C_COLLATION)
        .pluck(
          Arel.sql(card), IDENTIFIER_C_COLLATION,
          *window_flag_selects(7, from_7), *window_flag_selects(30, from_30)
        ).map { |values| WINDOW_FLAG_KEYS.zip(values).to_h }
      # rubocop:enable Database/AvoidUsingPluckWithoutLimit
    end

    def self.window_flag_card
      whens = rule_types.map do |name, value|
        vulnerability_family = ::Security::DependencyFirewallPolicyRule.severity_carrying_types.include?(name)
        card = vulnerability_family ? 'vulnerabilities' : name
        "WHEN #{value} THEN #{connection.quote(card)}"
      end

      "CASE rule_type #{whens.join(' ')} END"
    end

    def self.window_flag_selects(days, from)
      quoted_from = connection.quote(from)
      blocked = "last_blocked_at >= #{quoted_from}"
      warned_only = "last_warned_at >= #{quoted_from} AND (last_blocked_at IS NULL OR last_blocked_at < #{quoted_from})"

      [
        Arel.sql("COALESCE(bool_or(#{blocked}), FALSE) AS blocked_#{days}"),
        Arel.sql("COALESCE(bool_or(#{warned_only}), FALSE) AS warned_only_#{days}"),
        Arel.sql("MAX(severity) FILTER (WHERE #{blocked}) AS max_severity_#{days}")
      ]
    end
    private_class_method :window_flag_card, :window_flag_selects

    # Rows must be pre-folded by unique key: PostgreSQL raises "cannot affect row a second time"
    # when one upsert statement carries duplicate conflict targets.
    def self.bulk_upsert!(rows)
      return if rows.empty?

      rows.each { |row| validate_enum_values!(row) }

      upsert_all(rows, unique_by: 'i_dep_fw_prevented_packages_unique', on_duplicate: ON_DUPLICATE_MERGE)
    end

    # No CHECK constraint bounds either column, and an unmapped value inserts and then reads back
    # as nil: invisible to the read scopes while still holding that package's unique slot, and
    # poisoning the GREATEST merge thereafter. upsert_all does cast enum keys, so accept those too.
    def self.validate_enum_values!(row)
      rule_type = row[:rule_type]
      raise InvalidEnumValueError, "'#{rule_type}' is not a valid rule_type" unless valid_enum?(rule_types, rule_type)

      severity = row[:severity]
      return if severity.nil? || valid_enum?(severities, severity)

      raise InvalidEnumValueError, "'#{severity}' is not a valid severity"
    end

    def self.valid_enum?(mapping, value)
      mapping.key?(value) || mapping.value?(value)
    end
    private_class_method :validate_enum_values!, :valid_enum?

    private

    # Model mirror of check_dep_fw_prevented_packages_severity_rule_type (bulk_upsert! relies on
    # the DB constraint; instance writes fail at the boundary instead).
    def severity_only_for_vulnerability_rules
      return if severity.nil? ||
        ::Security::DependencyFirewallPolicyRule.severity_carrying_types.include?(rule_type)

      errors.add(:severity, 'is only valid for vulnerability-family rule types')
    end

    # Model mirror of check_dep_fw_prevented_packages_timestamps: a row with neither timestamp is
    # invisible to both read scopes while still holding that package's unique slot.
    def at_least_one_prevention_timestamp
      return if last_blocked_at.present? || last_warned_at.present?

      errors.add(:base, 'must set last_blocked_at or last_warned_at')
    end
  end
end
