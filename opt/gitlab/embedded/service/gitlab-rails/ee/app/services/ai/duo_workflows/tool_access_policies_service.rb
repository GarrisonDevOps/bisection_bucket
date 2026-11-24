# frozen_string_literal: true

module Ai
  module DuoWorkflows
    # Resolves the tool access policy DWS enforces for a session, for both the token claim
    # and the workflow's toolAccessPolicies GraphQL field.
    class ToolAccessPoliciesService
      def initialize(workflow:, root_namespace:, project:, environment:, mcp_config_service:, request_namespace: nil)
        @workflow = workflow
        @root_namespace = root_namespace
        @project = project
        @environment = environment
        @mcp_config_service = mcp_config_service
        @request_namespace = request_namespace
      end

      # root_namespace and project are caller-supplied, so a policy resolved from them is
      # not necessarily the one the executed workflow is subject to.
      def execute
        container = workflow&.resource_parent

        # Without a container everything below falls back to the request context, which
        # is what this no longer trusts.
        return no_tool_access_policies if workflow && container.nil?

        governance_namespace = container&.root_ancestor || root_namespace
        governance_surface = governance_surface_for(container, governance_namespace)

        own_project =
          if container.is_a?(::Project)
            container
          elsif workflow.nil?
            project
          end

        # The lists must stay empty: DWS reads empty allow/ask/deny as governance inactive and
        # keeps the client's pre-approvals. A non-empty allow would replace them.
        # Pinned DWS-side by test_compile_and_run_graph_keeps_client_preapproved_when_governance_inactive.
        if ::Ai::ToolRules::GovernanceSurface.ungoverned?(governance_surface)
          return ungoverned_tool_access_policies(governance_namespace, own_project)
        end

        governance_surface ||= :web

        policy = resolve_rules(governance_namespace, governance_surface, own_project)
        return no_tool_access_policies unless policy

        policy = tighten_with_requested_project(policy, governance_namespace, governance_surface, own_project)

        # MCP pre-approvals are appended after governance has resolved, so a verdict
        # has to be subtracted again here or the append outlives it.
        allowed_tools = policy[:pre_approved_tools] + mcp_config_service.preapproved_tool_names
        allowed_tools -= policy[:ask_tools]
        allowed_tools -= policy[:denied_tools]

        policies = with_first_party_tools(
          { allow: allowed_tools.uniq, ask: policy[:ask_tools], deny: policy[:denied_tools] },
          governance_namespace,
          policy[:first_party_tools]
        )
        # Part of the policy itself, so a client cannot drop it the way it could a flag header.
        # Without a workflow, a subgroup rollout follows the project or namespace the request names.
        policies[:ceiling] = true if governance_ceiling?(container, own_project, governance_namespace)
        with_promote(
          policies, policy, governance_surface, requested_project_to_tighten(governance_namespace, own_project)
        )
      end

      private

      attr_reader :workflow, :root_namespace, :project, :environment, :mcp_config_service, :request_namespace

      # The ceiling only tightens, so following a caller-named namespace cannot loosen a session.
      def governance_ceiling?(container, own_project, governance_namespace)
        ::Ai::DuoWorkflows::GovernanceCeiling.enabled?(
          container || own_project || request_namespace || governance_namespace
        )
      end

      # Returns the raw surface. Defaulting to :web here would swallow UNGOVERNED, and an
      # ungoverned session must not be resolved at all.
      def governance_surface_for(container, governance_namespace)
        # `||` here would also fire for a workflow whose environment is nil, letting the
        # request pick the surface for a session it named.
        surface_environment = workflow ? workflow.environment : environment

        ::Ai::ToolRules::GovernanceSurface.for(
          environment: surface_environment,
          container: container || governance_namespace,
          workflow_definition: workflow&.workflow_definition
        )
      end

      def resolve_rules(namespace, surface, project)
        result = ::Ai::ToolRules::ResolutionService.new(
          namespace: namespace, surface: surface, project: project
        ).execute

        return unless result.success?

        result.payload.slice(:pre_approved_tools, :ask_tools, :denied_tools, :first_party_tools, :default_ask_tools)
      end

      # A project the workflow does not run in may only restrict this policy, never widen it.
      def tighten_with_requested_project(policy, namespace, surface, own_project)
        requested = requested_project_to_tighten(namespace, own_project)
        return policy unless requested

        # Falling back is safe: the workflow's own policy is already authoritative for it.
        tightened = resolve_rules(namespace, surface, requested)
        return policy unless tightened

        denied = policy[:denied_tools] | tightened[:denied_tools]
        {
          # Intersected, not subtracted: the project's own resolution is authoritative for what
          # it pre-approves, so a tool it leaves out drops here whether a rule or a group
          # verdict removed it.
          pre_approved_tools: policy[:pre_approved_tools] & tightened[:pre_approved_tools],
          ask_tools: (policy[:ask_tools] | tightened[:ask_tools]) - denied,
          denied_tools: denied,
          first_party_tools: most_restrictive_verdicts(policy[:first_party_tools], tightened[:first_party_tools]),
          default_ask_tools: Array(policy[:default_ask_tools]) & Array(tightened[:default_ask_tools])
        }
      end

      def requested_project_to_tighten(namespace, own_project)
        requested = project
        return if requested.nil? || requested == own_project
        return unless requested.root_ancestor.id == namespace.id

        requested
      end

      def most_restrictive_verdicts(verdicts, other_verdicts)
        verdicts.merge(other_verdicts) do |_tool_name, verdict, other_verdict|
          [verdict, other_verdict].max_by { |value| ::Ai::ToolRules::Permissions::RESTRICTIVENESS[value] }
        end
      end

      # Fail-closed: without first_party_tools DWS exempts no client tool, so it prompts.
      def no_tool_access_policies
        { allow: [], ask: [], deny: [] }
      end

      # Only the first-party map carries a verdict here, resolved from the stored rules like
      # the governed path: DWS still recognises first-party tools and honours an admin rule.
      def ungoverned_tool_access_policies(namespace, own_project)
        return no_tool_access_policies if ::Ai::ToolRules::FirstPartyTools.for(namespace).empty?

        verdicts = local_first_party_verdicts(namespace, own_project)
        requested = requested_project_to_tighten(namespace, own_project)
        verdicts = most_restrictive_verdicts(verdicts, local_first_party_verdicts(namespace, requested)) if requested

        no_tool_access_policies.merge(first_party_tools: verdicts)
      end

      # An ungoverned surface is always a local one, so local_access applies.
      def local_first_party_verdicts(namespace, project)
        ::Ai::ToolRules::ResolutionService.new(
          namespace: namespace, surface: ::Ai::ToolRules::GovernanceSurface::LOCAL, project: project
        ).first_party_verdicts
      end

      def with_promote(policies, policy, surface, requested_project)
        promote = ::Ai::ToolRules::AutoModePromotion.promote_list(
          policy: policy, surface: surface, container: workflow&.resource_parent, requested_project: requested_project
        )
        return policies if promote.nil?

        policies.merge(promote: promote - mcp_config_service.preapproved_tool_names)
      end

      # Flag off for the root group sends no key at all, which DWS already handles for an
      # older Rails.
      def with_first_party_tools(policies, governance_namespace, verdicts)
        return policies if ::Ai::ToolRules::FirstPartyTools.for(governance_namespace).empty?

        policies.merge(first_party_tools: verdicts)
      end
    end
  end
end
