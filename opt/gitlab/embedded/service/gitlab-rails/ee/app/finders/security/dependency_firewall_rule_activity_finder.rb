# frozen_string_literal: true

module Security
  # Builds the Dependency Firewall dashboard rows for a container (a group or a project): each
  # dependency firewall rule applicable to the container (its own and inherited policies), enabled
  # or disabled, with its block/warn activity over the relevant projects for the given date window.
  #
  # For the (low-frequency) dashboard read path only. It materialises every applicable rule and
  # resolves per-configuration Gitaly/last-modified data, which is unbounded, so it must not be
  # reused on performance-critical paths (e.g. CI enforcement) before the pagination and lazy
  # resolution in gitlab-org/gitlab#605638 land.
  class DependencyFirewallRuleActivityFinder
    RuleActivity = Struct.new(
      :rule, :policy_name, :enabled, :mode, :blocked_count, :warned_count, :activity_count, :scope,
      :source, :source_relationship, :last_modified_at, :last_modified_by, :container,
      keyword_init: true
    )

    # Server-side aggregate totals (not derived from the paginated rule list). The prevented_*
    # members come from the distinct-entity ledger (PreventedStats collectors), not the event
    # counter that feeds the other members.
    ActivitySummary = Struct.new(
      :blocked, :warned, :allowed, :total_triggers, :active_rules, :blocking_rules, :warning_rules,
      :vulnerabilities_prevented, :vulnerabilities_prevented_by_severity,
      :malicious_packages_prevented, :malicious_packages_warned_only,
      :license_risks_prevented, :license_risks_warned_only,
      keyword_init: true
    )

    DEFAULT_WINDOW_DAYS = 7

    # Maps the internal relationship to the shared SecurityPolicyRelationType enum values: our
    # "inherited" (ancestor-owned) is that enum's INHERITED_ONLY (its INHERITED means self+ancestors).
    SOURCE_RELATIONSHIP_ENUM = { self: :direct, inherited: :inherited_only, descendant: :descendant }.freeze

    def initialize(container, current_user, from: nil, to: nil)
      raise ::Gitlab::Graphql::Errors::ArgumentError, '`from` must be on or before `to`' if from && to && from > to

      @container = container
      @current_user = current_user
      @from = from
      @to = to
    end

    def execute
      return [] unless available?
      return [] if rule_policy_pairs.empty?

      counts = DependencyFirewallActivityStat.activity_counts_by_rule(
        rule_ids: rule_policy_pairs.map { |rule, _policy| rule.id },
        project_ids: activity_project_scope,
        time_range: time_range
      )

      scope_by_policy = {}
      source_by_policy = {}

      rule_policy_pairs.map do |rule, policy|
        rule_counts = counts.fetch(rule.id, { blocked: 0, warned: 0 })
        warn_mode = policy.enforcement_type_warn?

        RuleActivity.new(
          rule: rule,
          policy_name: policy.name,
          enabled: policy.enabled?,
          mode: warn_mode ? 'warn' : 'enforce',
          blocked_count: rule_counts[:blocked],
          warned_count: rule_counts[:warned],
          activity_count: warn_mode ? rule_counts[:warned] : rule_counts[:blocked],
          # Resolved once per policy (rules of the same policy share these) to avoid N+1.
          scope: (scope_by_policy[policy.id] ||= resolve_policy_scope(policy)),
          source: (source_by_policy[policy.id] ||= policy_source(policy)),
          source_relationship: source_relationship(policy),
          last_modified_at: policy.updated_at,
          last_modified_by: policy_last_modified_by(policy),
          container: container
        )
      end
    end

    # Aggregate totals across all rules/projects in scope (not the paginated rule list). Outcome
    # counts are summed in the database; rule counts are over the full applicable rule set.
    # "Total triggers" = blocked + warned + allowed.
    def activity_summary
      return empty_summary unless available?

      totals = DependencyFirewallActivityStat.outcome_totals(
        project_ids: activity_project_scope,
        time_range: time_range
      )
      blocked, warned, allowed = totals.values_at(:blocked, :warned, :allowed)
      # The rule list includes disabled rules, but the summary counts reflect only active (enabled)
      # rules, so the "active/blocking/warning rules" cards mean currently-enforcing rules.
      enabled_pairs = rule_policy_pairs.select { |_rule, policy| policy.enabled? }
      warning_rules = enabled_pairs.count { |_rule, policy| policy.enforcement_type_warn? }

      prevented = prevented_stats

      ActivitySummary.new(
        blocked: blocked,
        warned: warned,
        allowed: allowed,
        total_triggers: blocked + warned + allowed,
        active_rules: enabled_pairs.size,
        blocking_rules: enabled_pairs.size - warning_rules,
        warning_rules: warning_rules,
        vulnerabilities_prevented: prevented&.dig(:vulnerabilities, :prevented),
        vulnerabilities_prevented_by_severity: prevented&.dig(:vulnerabilities, :by_severity),
        malicious_packages_prevented: prevented&.dig(:malicious, :prevented),
        malicious_packages_warned_only: prevented&.dig(:malicious, :warned_only),
        license_risks_prevented: prevented&.dig(:license, :prevented),
        license_risks_warned_only: prevented&.dig(:license, :warned_only)
      )
    end

    private

    attr_reader :container, :current_user, :from, :to

    def available?
      ::Security::DependencyFirewall::Availability.available?(container) &&
        Ability.allowed?(current_user, :read_security_orchestration_policies, container)
    end

    def empty_summary
      ActivitySummary.new(
        blocked: 0, warned: 0, allowed: 0, total_triggers: 0,
        active_rules: 0, blocking_rules: 0, warning_rules: 0
      )
    end

    # nil when there is no group summary.
    def prevented_stats
      ::Security::DependencyFirewall::PreventedStats::DataCollector.new(
        container: container,
        from: prevented_stats_from
      ).counts
    end

    def prevented_stats_from
      return time_range.begin if from || !container.is_a?(Group)

      (Time.current.utc.to_date - (DEFAULT_WINDOW_DAYS - 1)).beginning_of_day
    end

    # Inclusive DEFAULT_WINDOW_DAYS-day window ending today. `to` is pushed to end-of-day so bare
    # Dates (from GraphQL DateType) don't drop same-day activity recorded after midnight.
    def time_range
      (from || (DEFAULT_WINDOW_DAYS - 1).days.ago).beginning_of_day..(to ? to.end_of_day : Time.current)
    end

    # Projects whose activity counts toward this dashboard: just the project at project level,
    # or every project in the hierarchy at group level (passed as a relation/subquery).
    def activity_project_scope
      container.is_a?(Project) ? [container.id] : container.all_projects
    end

    def resolve_policy_scope(policy)
      Security::SecurityOrchestrationPolicies::PolicyScopeFetcher.new(
        policy_scope: policy.scope&.deep_symbolize_keys || {},
        container: container,
        current_user: current_user
      ).execute
    end

    # Shaped for the reused SecurityPolicySource union (namespace present => group source).
    # `inherited` stays true only for ancestor-owned policies so the union keeps its existing
    # meaning; the dashboard distinguishes "defined below" via #source_relationship.
    def policy_source(policy)
      configuration = policy.security_orchestration_policy_configuration

      {
        namespace: configuration.namespace,
        project: configuration.project,
        inherited: relationship_for(configuration) == :inherited
      }
    end

    # Where the policy lives relative to the container being viewed: 'self' (defined here),
    # 'inherited' (defined in an ancestor group), or 'descendant' (defined in a subgroup/project
    # below this group). Drives the Source column wording ("This group" / "Inherited from" /
    # "Defined in"). Projects have no descendants, so a project only ever sees self/inherited.
    def source_relationship(policy)
      SOURCE_RELATIONSHIP_ENUM.fetch(relationship_for(policy.security_orchestration_policy_configuration))
    end

    def relationship_for(configuration)
      cache = (@relationship_by_configuration ||= {})

      cache.fetch(configuration.id) do
        cache[configuration.id] =
          if owned_by_container?(configuration)
            :self
          elsif container.is_a?(Project) || ancestor_namespace_ids.include?(configuration.namespace_id)
            :inherited
          else
            :descendant
          end
      end
    end

    def ancestor_namespace_ids
      @ancestor_namespace_ids ||= container.is_a?(Project) ? [] : container.ancestor_ids
    end

    # The user who last modified the policy's YAML (last MR author, else commit committer). This is
    # a Gitaly-backed call resolved once per configuration (policies in the same file share it).
    def policy_last_modified_by(policy)
      configuration = policy.security_orchestration_policy_configuration
      cache = (@last_modified_by_by_configuration ||= {})

      cache.fetch(configuration.id) do
        cache[configuration.id] = configuration.policy_last_updated_by
      end
    end

    def owned_by_container?(configuration)
      if container.is_a?(Project)
        configuration.project_id == container.id
      else
        configuration.namespace_id == container.id
      end
    end

    def rule_policy_pairs
      @rule_policy_pairs ||= dependency_firewall_policies.flat_map do |policy|
        policy.undeleted_dependency_firewall_policy_rules.map { |rule| [rule, policy] }
      end
    end

    def dependency_firewall_policies
      Security::Policy
        .for_policy_configuration_ids(configuration_ids)
        .type_dependency_firewall_policy
        .undeleted
        .preload_dependency_firewall_policy_rules
        .preload_configuration_namespace_and_project
    end

    # The effective set of policy configurations for the container, sourced from the persisted
    # configurations (not live-YAML validated) since the dashboard reflects synced records.
    # Projects: own config + ancestor group configs. Groups: the full vertical line, i.e. ancestor
    # namespaces (inherited), self, descendant subgroups, and every project in the hierarchy,
    # so the group view reflects everything being enforced at and below it.
    def configuration_ids
      configurations = Security::OrchestrationPolicyConfiguration

      if container.is_a?(Project)
        group_namespace_ids = Array(container.group&.self_and_ancestor_ids)
        namespace_scope = configurations.for_namespace(group_namespace_ids)
        project_scope = configurations.for_project(container.id)
      else
        namespace_ids = container.self_and_ancestor_ids | container.self_and_descendant_ids
        namespace_scope = configurations.for_namespace(namespace_ids)
        project_scope = configurations.for_project(container.all_projects.select(:id))
      end

      # Combine the namespace- and project-scoped configs with UNION ALL rather than an OR across
      # both columns, so each branch can use its partial index (namespace_id / project_id). ALL is
      # safe because a configuration is scoped to a namespace or a project, never both.
      configurations.from_union([namespace_scope, project_scope], remove_duplicates: false).select(:id)
    end
  end
end
