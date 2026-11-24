# frozen_string_literal: true

module EE
  module API
    module Mcp
      module Handlers
        module CallTool
          extend ActiveSupport::Concern
          extend ::Gitlab::Utils::Override

          prepended do
            include ::Gitlab::InternalEventsTracking
            include ::Gitlab::Utils::StrongMemoize
          end

          class SessionRefusedError < ::API::Mcp::Handlers::CallTool::ToolDeniedError
            def message
              format("Tool '%{tool_name}' is refused because its Duo session's workflow can't be resolved",
                tool_name: tool_name)
            end

            def result_text
              "#{tool_name} is refused because its Duo session's workflow can't be resolved."
            end
          end

          private

          override :failed_result
          def failed_result(result)
            return super unless result.is_a?(::Analytics::Orbit::CommandInterceptor::OrbitQuery)

            reason = result.response.error_reason
            ::Mcp::Tools::Base::Response.error('Orbit query failed', reason: reason) if reason
          end

          override :discard_result
          def discard_result(result)
            return super unless result.is_a?(::Analytics::Orbit::CommandInterceptor::OrbitQuery)

            body = result.response.body
            body.close if body.respond_to?(:close)
          end

          override :check_tool_governance!
          def check_tool_governance!(tool, tool_name, current_user, params)
            return unless ::Ai::ToolRules::McpGovernance.enabled_anywhere?

            containers = governed_readable_containers(tool, current_user, params)
            return if containers.empty?

            check_tool_rule!(containers, tool_name, current_user)
          end

          def governed_readable_containers(tool, current_user, params)
            tool_governed_containers(tool, params).containers.select do |container|
              ::Ai::ToolRules::McpGovernance.governs?(container) && container_readable?(container, current_user)
            end
          end

          def container_readable?(container, current_user)
            ability = container.is_a?(::Project) ? :read_project : :read_group

            ::Ability.allowed?(current_user, ability, container)
          end

          def check_tool_rule!(containers, tool_name, current_user)
            surface = governance_surface(current_user)
            governance = ::Ai::ToolRules::McpGovernance.new(containers, surface: surface)
            canonical = canonical_tool_name(tool_name)
            return unless governance.permission_for(canonical) == ::Ai::ToolRules::Permissions::DENY

            raise SessionRefusedError, tool_name if ::Ai::ToolRules::GovernanceSurface.refused?(surface)

            raise ::API::Mcp::Handlers::CallTool::ToolDeniedError.new(
              tool_name, readable_denier(governance.denied_by(canonical), current_user)
            )
          end

          def governance_surface(current_user)
            ::Ai::ToolRules::McpCallerSurface.for(context&.access_token, current_user)
          end

          def readable_denier(container, current_user)
            return unless container && container_readable?(container, current_user)

            container.full_path
          end

          def canonical_tool_name(tool_name)
            manager.resolve_alias(tool_name)
          end

          # Memoized by the start event, which runs before the tool: aggregated tools reassign
          # params[:arguments] to the shape they dispatch, so a later read would see that instead.
          def arguments_as_sent(params)
            strong_memoize(:arguments_as_sent) { params.to_h.with_indifferent_access[:arguments] || {} }
          end

          def tool_governed_containers(tool, params)
            strong_memoize(:tool_governed_containers) do
              tool.governed_containers(arguments_as_sent(params))
            end
          end

          def track_start_event(tool_name, request_id, current_user, tool: nil, params: nil)
            arguments_as_sent(params)

            track_internal_event(
              'start_mcp_tool_call',
              user: current_user,
              **resolve_tracking_scope(tool, params),
              additional_properties: {
                request_id: request_id,
                tool_name: tool_name,
                **alias_fields(tool_name),
                **client_fields
              }
            )
          end

          # rubocop:disable Metrics/ParameterLists -- mirrors the CE signature it overrides
          def track_finish_event(
            tool_name, request_id, current_user, success:, tool: nil, error: nil, params: nil,
            duration_s: nil, dispatch: nil
          )
            # rubocop:enable Metrics/ParameterLists
            failure_reason = error && tool_status(error)
            additional_properties = {
              request_id: request_id,
              tool_name: tool_name,
              **alias_fields(tool_name),
              has_tool_call_success: success.to_s,
              **client_fields,
              **dispatch_fields(dispatch)
            }

            additional_properties[:normalized_arguments] = normalized_arguments.join(',') if normalized_arguments

            if error
              additional_properties[:failure_reason] = failure_reason
              additional_properties[:error_status] = error.message&.truncate(255)
            end

            track_internal_event(
              'finish_mcp_tool_call',
              user: current_user,
              **resolve_tracking_scope(tool, params),
              additional_properties: additional_properties
            )

            # Every call is an invocation, so a blocked one still counts in "tools invoked".
            # A failure adds a second event.
            capture_audit_events(
              success ? %i[tool_invoked] : %i[tool_invoked tool_failed],
              tool_name, current_user, tool: tool, params: params, error: error, duration_s: duration_s,
              dispatched_tool_name: dispatch&.dig(:tool_name), failure_reason: failure_reason
            )
          end

          def capture_audit_events(kinds, tool_name, current_user, tool:, params:, **extra)
            # Checked first against the scope logging already resolved, so with the flag off a call
            # pays for none of the membership and default namespace lookups below.
            return unless ::Feature.enabled?(:mcp_session_audit_events, tool_call_namespace(tool, params))

            container = audit_session_container(current_user, tool, params)
            # Checked again against where the event goes, since a non-member's call falls back to their own namespace.
            return unless ::Feature.enabled?(:mcp_session_audit_events, container&.root_ancestor)

            session = audit_session(current_user, container)
            return unless session

            arguments = filter_parameters(arguments_as_sent(params))

            # One job for both events of a failed call.
            events = kinds.map do |kind|
              ::Mcp::Audit::CaptureEventService.new(
                current_user: current_user,
                session: session,
                kind: kind,
                tool_name: tool_name,
                arguments: arguments,
                **extra
              ).job_attributes
            end

            ::Ai::DuoWorkflows::ProcessAuditEventsWorker.perform_async(events)
          rescue StandardError => e
            ::Gitlab::ErrorTracking.track_exception(e, mcp_tool: tool_name)
          end

          def audit_session(current_user, container)
            ::Mcp::Audit::ResolveSessionService.new(current_user: current_user, container: container).execute
          end

          # Membership, not readability: a public project is readable by any signed-in user, so a
          # read check would put a non-member's identity and arguments into the owner's audit stream.
          def audit_session_container(current_user, tool, params)
            scope = resolve_tracking_scope(tool, params)

            project = scope[:project]
            return project if project && member_of?(current_user, project.team)

            namespace = scope[:namespace]
            return namespace if namespace && member_of?(current_user, namespace)

            current_user.user_preference.duo_default_namespace_with_fallback || current_user.namespace
          end

          # Instance admins and organization owners count as OWNER in both sources, so their calls
          # stay scoped to the resource rather than collapsing onto their own namespace. Neither is
          # an outsider: both already administer the resource.
          def member_of?(current_user, source)
            source.max_member_access_for_user(current_user) >= ::Gitlab::Access::GUEST
          end

          def tool_call_namespace(tool, params)
            scope = resolve_tracking_scope(tool, params)
            (scope[:project] || scope[:namespace])&.root_ancestor
          end

          def resolve_tracking_scope(tool, params)
            strong_memoize(:resolved_tracking_scope) do
              containers = tracking_containers(tool, params)

              {
                project: containers.find { |container| container.is_a?(::Project) },
                namespace: containers.find { |container| container.is_a?(::Group) }
              }.compact
            end
          end

          def tracking_containers(tool, params)
            return [] unless tool

            tool_governed_containers(tool, params).containers
          rescue ArgumentError
            []
          rescue StandardError => e
            ::Gitlab::ErrorTracking.track_exception(e, mcp_tool: params[:name])
            []
          end
        end
      end
    end
  end
end
