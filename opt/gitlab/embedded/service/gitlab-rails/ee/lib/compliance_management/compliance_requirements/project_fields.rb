# frozen_string_literal: true

module ComplianceManagement
  module ComplianceRequirements
    class ProjectFields
      FIELD_MAPPINGS = ComplianceManagement::ComplianceFramework::Controls::Registry.field_mappings.dup
        .tap do |mappings|
        mappings.delete_if { |k, _| k.start_with?('minimum_approvals_required_') }
        mappings['minimum_approvals_required'] = :minimum_approvals_required
      end.freeze

      SECURITY_SCANNERS = [
        :sast,
        :secret_detection,
        :dependency_scanning,
        :container_scanning,
        :license_scanning,
        :dast,
        :api_fuzzing,
        :codequality,
        :iac
      ].freeze

      ROLE_ACCESS_LEVELS = {
        developer: Gitlab::Access::DEVELOPER,
        maintainer: Gitlab::Access::MAINTAINER
      }.freeze

      DUO_AGENTIC_FLOW_CORE_EVENT_TYPES = %w[
        duo_session_started
        duo_session_stopped
        duo_tool_call_approved
        flow_trigger_created
        flow_trigger_deleted
        duo_workflow_mcp_enabled_updated
      ].freeze

      DUO_AGENTIC_FLOW_MINIMUM_CORE_EVENT_TYPES = 3

      class << self
        def map_field(project, field, context = {})
          method_name = FIELD_MAPPINGS[field]
          return unless method_name

          send(method_name, project, context) # rubocop:disable GitlabSecurity/PublicSend -- We control the `method` name
        end

        private

        ##
        ## Helper Methods
        ##

        def security_scanner_running?(scanner, project, _context = {})
          return false unless SECURITY_SCANNERS.include?(scanner)

          pipeline = project.latest_pipeline_for_ci_and_security_orchestration

          return false if pipeline.nil?

          pipeline.job_artifacts.send(scanner).any? # rubocop: disable GitlabSecurity/PublicSend -- limited to supported scanners
        end

        ##
        ## Control Methods
        ##

        def default_branch_protected?(project, _context = {})
          return false unless project.default_branch

          ProtectedBranch.protected?(project, project.default_branch)
        end

        def merge_request_prevent_author_approval?(project, context = {})
          settings_prevent_approval?("prevent_approval_by_author", context) ||
            !project.merge_requests_author_approval?
        end

        def merge_requests_disable_committers_approval?(project, context = {})
          settings_prevent_approval?("prevent_approval_by_commit_author", context) ||
            project.merge_requests_disable_committers_approval?
        end

        def minimum_approvals_required(project, _context = {})
          project.approval_rules.pick("SUM(approvals_required)") || 0
        end

        def auth_sso_enabled?(project, _context = {})
          return true if ::Gitlab::Auth::Saml::Config.sign_in_enabled?
          return false unless project.group

          ::Groups::SsoHelper.saml_provider_enabled?(project.group) &&
            ::Gitlab::Auth::GroupSaml::Config.sign_in_enabled?
        end

        def scanner_sast_running?(project, context = {})
          security_scanner_running?(:sast, project, context)
        end

        def scanner_secret_detection_running?(project, context = {})
          security_scanner_running?(:secret_detection, project, context)
        end

        def scanner_dep_scanning_running?(project, context = {})
          security_scanner_running?(:dependency_scanning, project, context)
        end

        def scanner_container_scanning_running?(project, context = {})
          security_scanner_running?(:container_scanning, project, context)
        end

        def scanner_license_compliance_running?(project, context = {})
          security_scanner_running?(:dependency_scanning, project, context)
        end

        def scanner_dast_running?(project, context = {})
          security_scanner_running?(:dast, project, context)
        end

        def scanner_api_security_running?(project, context = {})
          security_scanner_running?(:api_fuzzing, project, context) ||
            security_scanner_running?(:dast, project, context)
        end

        def scanner_code_quality_running?(project, context = {})
          security_scanner_running?(:codequality, project, context)
        end

        def scanner_iac_running?(project, _context = {})
          pipeline = ::Ci::ProjectPipelines.new(project).latest_in_default_branch

          return false if pipeline.nil?

          pipeline.builds.iac_sast_jobs.with_sast_artifacts.exists?
        end

        def code_changes_requires_code_owners?(project, _context = {})
          return false unless project.default_branch

          ProtectedBranch.branch_requires_code_owner_approval?(project, project.default_branch)
        end

        def stale_branch_cleanup_enabled?(project, _context = {})
          !BranchesFinder.new(project.repository,
            { per_page: 1, sort: 'updated_asc' }).execute(gitaly_pagination: true).any?(&:stale?)
        end

        def project_repo_exists?(project, _context = {})
          project.repository.exists?
        end

        def issue_tracking_enabled?(project, _context = {})
          owner = Project.owners.first
          recent_mr_limit = 20

          project.merge_requests.merged.order_merged_at_desc.limit(recent_mr_limit).all? do |mr|
            mr.related_issues(owner).any?
          end
        end

        def reset_approvals_on_push?(project, _context = {})
          project.reset_approvals_on_push
        end

        def protected_branches_set?(project, _context = {})
          project.all_protected_branches.any?
        end

        def code_owner_approval_required?(project, _context = {})
          Gitlab::CodeOwners::Loader.new(project, project.default_branch).has_code_owners_file?
        end

        def status_checks_required?(project, _context = {})
          project.only_allow_merge_if_all_status_checks_passed
        end

        def require_branch_up_to_date?(project, _context = {})
          [:rebase_merge, :ff].include?(project.merge_method)
        end

        def resolve_discussions_required?(project, _context = {})
          project.only_allow_merge_if_all_discussions_are_resolved
        end

        def require_signed_commits?(project, _context = {})
          !!(project.push_rule && project.push_rule.reject_unsigned_commits)
        end

        def require_linear_history?(project, _context = {})
          [:rebase_merge, :merge].exclude?(project.merge_method)
        end

        def restrict_push_merge_access?(project, _context = {})
          !project.all_protected_branches.any?(&:allow_force_push)
        end

        def force_push_disabled?(project, _context = {})
          !ProtectedBranch.allow_force_push?(project, nil)
        end

        def terraform_enabled?(project, _context = {})
          project.terraform_states.exists?
        end

        def settings_prevent_approval?(setting_key, context = {})
          approval_settings = context[:approval_settings]
          return false if approval_settings.blank?

          approval_settings.any? do |settings|
            next false unless settings.is_a?(Hash)

            settings[setting_key] == true
          end
        end

        def branch_deletion_disabled?(project, _context = {})
          ProtectedBranch.protected_refs(project).any?
        end

        def has_forks?(project, _context = {})
          project.forks.any?
        end

        def review_and_archive_stale_repos?(project, _context = {})
          stale_threshold = 6.months.ago

          return true if project.self_or_ancestors_archived?

          project.last_activity_at > stale_threshold
        end

        def review_and_remove_inactive_users?(project, _context = {})
          stale_threshold = 90.days.ago

          project.team.users.none? { |user| user.last_activity_on.nil? || user.last_activity_on < stale_threshold }
        end

        def more_members_than_admins?(project, _context = {})
          team = project.team

          return true if team.members.count == 1

          team.members.count > (team.owners + team.maintainers).count
        end

        def require_mfa_for_contributors?(project, _context = {})
          project.namespace.require_two_factor_authentication
        end

        def require_mfa_at_org_level?(project, _context = {})
          project.namespace.require_two_factor_authentication || project.namespace.two_factor_grace_period != 0
        end

        def ensure_2_admins_per_repo?(project, _context = {})
          project.team.owners.count >= 2
        end

        def strict_permissions_for_repo?(project, _context = {})
          team = project.team

          return true if team.members.count == 1

          team.members.count > (team.owners + team.maintainers).count
        end

        def secure_webhooks?(project, _context = {})
          project.hooks.all? { |hook| hook.url.start_with?('https') }
        end

        def restricted_build_access?(project, _context = {})
          team = project.team
          reporter_and_above = (team.owners + team.maintainers + team.developers + team.reporters).count.to_f
          return true if reporter_and_above < 3

          total_members = team.members.count.to_f
          reporter_and_above_percentage = (reporter_and_above / total_members) * 100

          reporter_and_above_percentage < 40
        end

        def gitlab_license_level_ultimate?(project, _context = {})
          License.current.ultimate? &&
            (project.licensed_features & GitlabSubscriptions::Features::ULTIMATE_FEATURES).any?
        end

        def status_page_configured?(project, _context = {})
          project&.feature_available?(:status_page) || project&.licensed_feature_available?(:status_page)
        end

        def has_valid_ci_config?(project, _context = {})
          return false unless project.has_ci? && project.builds_enabled?

          begin
            yml_dump = project.ci_config_for(project.default_branch)
            sha = project.repository.root_ref_sha
            return false if sha.nil?

            config = Gitlab::Ci::Config.new(
              yml_dump,
              project: project,
              user: project.first_owner,
              sha: sha,
              ref: project.default_branch
            )
            config.valid?
          rescue Gitlab::Ci::Config::ConfigError, Gitlab::Ci::Config::External::Context::TimeoutError
            false
          end
        end

        def error_tracking_enabled?(project, _context = {})
          project.error_tracking_setting&.enabled? || false
        end

        def default_branch_users_can_push?(project, context = {})
          # Checks if a role can push to the default branch, by default checks against Maintainer role
          role = context[:role] || :maintainer

          return false if project.empty_repo? || !default_branch_protected?(project)

          role_access_level = ROLE_ACCESS_LEVELS[role.to_sym] || Gitlab::Access::MAINTAINER

          protected_branch = project.protected_branches.find_by(name: project.default_branch) # rubocop:disable CodeReuse/ActiveRecord -- Need to find Branch by string name
          return false unless protected_branch

          protected_branch.push_access_levels.any? do |access_level|
            access_level.respond_to?(:role?) &&
              access_level.role? &&
              access_level.access_level >= role_access_level
          end
        end

        def default_branch_protected_from_direct_push?(project, _context = {})
          return false if project.default_branch.nil? || project.empty_repo? || !default_branch_protected?(project)

          !default_branch_users_can_push?(project, role: :developer) &&
            !default_branch_users_can_push?(project, role: :maintainer) &&
            !default_branch_users_can_push?(project, role: :owner)
        end

        def push_protection_enabled?(project, _context = {})
          project.security_setting&.secret_push_protection_enabled
        end

        def project_visibility_not_internal?(project, _context = {})
          !project.internal?
        end

        def project_archived?(project, _context = {})
          project.self_or_ancestors_archived?
        end

        def default_branch_users_can_merge?(project, _context = {})
          # No default branch means no restrictions - return false as there is no default branch
          return false unless project.default_branch

          protected_branch = ProtectedBranch.default_branch_for(project)

          return false unless protected_branch # Return false - Unprotected branch means anyone can merge

          # Check if any merge access level allows developers or higher roles to merge
          protected_branch.merge_access_levels.any? do |access_level|
            access_level.role? && access_level.access_level >= Gitlab::Access::DEVELOPER
          end
        end

        def merge_request_commit_reset_approvals?(project, _context = {})
          project.reset_approvals_on_push?
        end

        def project_visibility_not_public?(project, _context = {})
          !project.public?
        end

        def package_hunter_no_findings_untriaged?(project, _context = {})
          return false unless project.licensed_feature_available?(:security_dashboard)

          finder = ::Security::VulnerabilityReadsFinder.new(
            project,
            {
              scanner: %w[packagehunter],
              state: %w[detected confirmed]
            }
          )
          finder.execute.any?
        end

        def project_pipelines_not_public?(project, _context = {})
          # Goes in order of: disabled, private, enabled, public

          project.project_feature.access_level(:builds) < ProjectFeature.access_level_from_str('enabled')
        end

        def vulnerabilities_slo_days_over_threshold?(project, context = {})
          threshold = context[:threshold] || 180 # Days

          oldest_vulnerability = project.vulnerabilities
            .with_states(Vulnerability::ACTIVE_STATES)
            .order_created_at_asc
            .with_limit(1)
            .first

          return false if oldest_vulnerability.nil?

          oldest_vulnerability.created_at < threshold.days.ago
        end

        def merge_requests_approval_rules_prevent_editing?(project, _context = {})
          project.disable_overriding_approvers_per_merge_request?
        end

        def project_user_defined_variables_restricted_to_maintainers?(project, _context = {})
          return false unless project&.ci_cd_settings

          project.restrict_user_defined_variables?
        end

        def merge_requests_require_code_owner_approval?(project, _context = {})
          project.merge_requests_require_code_owner_approval?
        end

        def cicd_job_token_scope_enabled?(project, _context = {})
          project.ci_inbound_job_token_scope_enabled?
        end

        def project_marked_for_deletion?(project, _context = {})
          project.self_deletion_scheduled?
        end

        def model_registry_access_level_configured?(project, _context = {})
          return true unless Ml::ModelVersion.by_project(project).exists?

          project.project_feature.access_level(:model_registry) <= ProjectFeature::PRIVATE
        end

        def model_experiments_access_level_configured?(project, _context = {})
          return true unless Ml::Experiment.by_project(project).exists?

          project.project_feature.access_level(:model_experiments) <= ProjectFeature::PRIVATE
        end

        def duo_agentic_flow_audit_events_streaming?(project, _context = {})
          group = project.group
          return false unless group

          # Short-circuit: if the Agent Platform is disabled, treat as compliant.
          # TODO: Replace with NOT_APPLICABLE when implemented in #621132
          # https://gitlab.com/gitlab-org/gitlab/-/work_items/621132
          return true unless ::Ai::DuoWorkflow.duo_agent_platform_available?(group)

          # Streaming destinations can only be configured on top-level groups.
          active_destinations = group.root_ancestor.external_audit_event_streaming_destinations.active.preload_filters

          group_and_ancestor_ids = group.self_and_ancestor_ids

          active_destinations.any? do |destination|
            next false if streaming_destination_excludes_group?(destination, group_and_ancestor_ids)

            streaming_destination_covers_duo_event_types?(destination)
          end
        end

        def streaming_destination_excludes_group?(destination, group_and_ancestor_ids)
          namespace_filters = destination.namespace_filters
          return false if namespace_filters.empty?

          namespace_filters.none? { |filter| group_and_ancestor_ids.include?(filter.namespace_id) }
        end

        def streaming_destination_covers_duo_event_types?(destination)
          # The streamer consults the denylist first, so denylisted core types
          # never reach the destination, even with an empty allowlist.
          streamable_core_types = DUO_AGENTIC_FLOW_CORE_EVENT_TYPES -
            destination.event_type_denylist_filters.map(&:audit_event_type)

          allowlist_filters = destination.event_type_filters
          return streamable_core_types.size >= DUO_AGENTIC_FLOW_MINIMUM_CORE_EVENT_TYPES if allowlist_filters.empty?

          covered_count = allowlist_filters.count do |filter|
            streamable_core_types.include?(filter.audit_event_type)
          end

          covered_count >= DUO_AGENTIC_FLOW_MINIMUM_CORE_EVENT_TYPES
        end

        def duo_agentic_flow_governance_oversight_configured?(project, _context = {})
          return :not_applicable unless project.group
          return :not_applicable unless ::Ai::DuoWorkflow.duo_agent_platform_available?(project)

          # Same scope the firing path uses: active project triggers plus inherited group triggers.
          flow_triggers = ::Ai::FlowTrigger.applicable_to_project(project).to_a

          flow_triggers.any? &&
            mcp_explicitly_configured?(project) &&
            no_ungated_broad_scope_trigger?(project, flow_triggers)
        end

        ##
        ## Helpers for duo_agentic_flow_governance_oversight_configured?
        ##

        def mcp_explicitly_configured?(project)
          # The provenance key is written only on explicit submission, even of the default value;
          # record presence is not a signal. Unsaved built records default `configured_at` to {}.
          project.root_ancestor.ai_settings.configured_at.key?('duo_workflow_mcp_enabled')
        end

        def no_ungated_broad_scope_trigger?(project, flow_triggers)
          broad_scope_triggers = flow_triggers.select { |t| broad_scope_trigger?(t) }
          return true if broad_scope_triggers.empty?

          gated_by_approval_policy?(project, broad_scope_triggers)
        end

        # Approval policies gate MRs by target branch while a broad-scope trigger fires on any push,
        # so "gated" means an enforced (non-warn) policy requires at least one approval on every MR
        # to every protected branch, and the flow cannot bypass it.
        def gated_by_approval_policy?(project, broad_scope_triggers)
          project.approval_policies
            .without_warn_mode
            .preload_approval_policy_rules
            .any? do |policy|
              requires_approval?(policy) &&
                policy.undeleted_approval_policy_rules.any? { |rule| gates_every_protected_branch_mr?(rule) } &&
                !bypassable_by_flow?(policy, broad_scope_triggers)
            end
        end

        def requires_approval?(policy)
          policy.approval_policy.actions.require_approval_actions.any? { |action| action.approvals_required.to_i >= 1 }
        end

        # Role, group, and custom role bypasses are not evaluated.
        def bypassable_by_flow?(policy, broad_scope_triggers)
          bypass_settings = policy.bypass_settings
          return true if bypass_settings.branches.any?
          return false if bypass_settings.service_account_ids.empty?

          broad_scope_triggers.any? { |t| bypass_settings.service_account_ids.include?(t.service_account_id) }
        end

        # Rules for scan or license findings, or unsigned commits, only require approval on some MRs.
        def gates_every_protected_branch_mr?(rule)
          rule.type_any_merge_request? &&
            rule.commits_any? &&
            rule.rule.branch_exceptions.empty? &&
            protected_branches_rule?(rule)
        end

        # Policies only apply to protected branches, so a `*` pattern resolves to all of them, like `[]`.
        def protected_branches_rule?(rule)
          branches = rule.content['branches']

          branches == [] || branches&.include?('*') || rule.content['branch_type'] == 'protected'
        end

        # Autonomous (scheduled) triggers run with no human initiator and are not branch-scoped.
        def broad_scope_trigger?(trigger)
          trigger.autonomous_only? || broad_scope_pipeline_trigger?(trigger)
        end

        # A pipeline_hooks trigger with no ref filter runs on every branch push
        # (the functional equivalent of a wildcard (*) branch pattern).
        def broad_scope_pipeline_trigger?(trigger)
          pipeline_hooks_id = ::Ai::FlowTrigger::EVENT_TYPES[:pipeline_hooks]
          return false unless trigger.event_types.include?(pipeline_hooks_id)

          filter = trigger.filter
          return true if filter.blank?

          pipeline_filter = filter['pipeline_hooks']
          return true if pipeline_filter.blank?

          !ref_restricted?(pipeline_filter)
        end

        # Mirrors Gitlab::FilterEvaluator group semantics: an `all` group (the default) restricts the ref
        # if any child does, any other match type only if every child does.
        def ref_restricted?(group, depth = 1)
          return false unless group.is_a?(Hash)
          return false if depth > Gitlab::FilterEvaluator::MAX_DEPTH

          results = Array(group['rules']).map do |rule|
            next false unless rule.is_a?(Hash)

            rule['type'] == 'group' ? ref_restricted?(rule, depth + 1) : ref_restricting_rule?(rule)
          end

          (group['match'] || 'all') == 'all' ? results.any? : results.present? && results.all?
        end

        # Only eq/in narrow the ref. Negative operators and `contains` can match arbitrary branches,
        # so they do not count. `default_branch == true` is equivalent to `ref == <default branch>`.
        def ref_restricting_rule?(rule)
          return false unless %w[eq in].include?(rule['operator'])

          case rule['field']
          when 'object_attributes.ref' then true
          when 'object_attributes.default_branch' then Array(rule['value']) == [true]
          else false
          end
        end
      end
    end
  end
end
