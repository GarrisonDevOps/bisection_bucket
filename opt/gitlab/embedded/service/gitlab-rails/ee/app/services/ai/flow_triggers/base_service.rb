# frozen_string_literal: true

module Ai
  module FlowTriggers
    # Applies shared validation, authorization, compatibility, and audit behavior to flow-trigger mutations.
    #
    # User-driven services continue to require +:manage_ai_flow_triggers+. A create service may carry a
    # typed inherited-project authorization that bypasses only that actor-role check for the exact computed
    # foundational-flow consumer. Model validation, service-account alignment, and composite-identity
    # enforcement remain unchanged.
    class BaseService
      attr_reader :project, :current_user, :authorization_context

      ERROR_REASON_UNAUTHORIZED = :unauthorized
      ERROR_REASON_SERVICE_ACCOUNT_MISMATCH = :service_account_mismatch
      ERROR_REASON_INVALID_TRIGGER = :validation_error
      ERROR_REASON_INSUFFICIENT_SERVICE_ACCOUNT_ACCESS = :insufficient_service_account_access

      def execute(params)
        return system_event_types_error if system_event_types_changed?(params)

        params = params.dup
        authorization_params = params.dup

        service_account = service_account(params[:user_id])
        ai_catalog_item_consumer = ai_catalog_item_consumer(params[:ai_catalog_item_consumer_id])

        params[:user_id] = nil if ai_catalog_item_consumer.present?

        unless user_is_authorized_to_service_account?(service_account, ai_catalog_item_consumer, authorization_params)
          return ServiceResponse.error(
            message: 'You are not authorized to use this service account in this project',
            reason: ERROR_REASON_UNAUTHORIZED
          )
        end

        unless service_account_compatible_with_item_consumer?(service_account, ai_catalog_item_consumer)
          return misaligned_service_account_error
        end

        response = nil
        dropped_service_account_id = nil
        reused_service_account_id = nil

        # A provisioned account must not outlive a trigger that fails validation.
        ApplicationRecord.transaction do
          assigned = assign_autonomous_service_account(params, ai_catalog_item_consumer)

          if assigned.error?
            response = assigned
            raise ActiveRecord::Rollback
          end

          # An edit that drops the autonomous events gives the flow back to
          # the consumer's shared account.
          dropped_service_account_id = assigned.payload[:dropped_service_account_id]
          reused_service_account_id = assigned.payload[:reused_service_account_id]

          trigger = yield(params)

          if trigger.valid?
            enforce_composite_identity!(service_account) unless trigger.autonomous_only?

            response = ServiceResponse.success(payload: trigger)
          else
            response = ServiceResponse.error(
              message: trigger.errors.full_messages.to_sentence, reason: ERROR_REASON_INVALID_TRIGGER
            )
            raise ActiveRecord::Rollback
          end
        end

        # Membership changes have their own side effects, and a failed one must
        # not rollback the trigger change, so both run only once the trigger
        # change is committed. A raised error here cannot roll anything back.
        if response.success?
          if dropped_service_account_id
            revoke_dedicated_account_access(User.find_by_id(dropped_service_account_id), response.payload.project)
          end

          sync_access_level(reused_service_account_id, ai_catalog_item_consumer) if reused_service_account_id
        end

        response
      end

      private

      def service_account(service_account_id)
        return unless service_account_id.present?

        User.find_by_id(service_account_id)
      end

      def ai_catalog_item_consumer(ai_catalog_item_consumer_id)
        return unless ai_catalog_item_consumer_id.present?

        @ai_catalog_item_consumers ||= {}

        if @ai_catalog_item_consumers.key?(ai_catalog_item_consumer_id)
          return @ai_catalog_item_consumers[ai_catalog_item_consumer_id]
        end

        @ai_catalog_item_consumers[ai_catalog_item_consumer_id] =
          Ai::Catalog::ItemConsumer.find_by_id(ai_catalog_item_consumer_id)
      end

      # Inherited authorization never accepts a manually supplied service account.
      def user_is_authorized_to_service_account?(service_account, ai_catalog_item_consumer, params)
        if authorization_context
          return authorization_context.authorized_for_trigger?(
            project: project,
            item_consumer: ai_catalog_item_consumer,
            params: params
          )
        end

        allowed = authorized_to_manage?
        return allowed if service_account.nil? || allowed == false

        return false unless service_account.service_account?

        group = service_account.provisioned_by_group

        return false unless group
        return false unless group.root_ancestor.id == container.root_ancestor.id

        true
      end

      def authorized_to_manage?
        Ability.allowed?(current_user, :manage_ai_flow_triggers, permission_subject)
      end

      def permission_subject
        @trigger
      end

      def container
        @trigger.container
      end

      # The trigger's attributes before this call: these defaults on create, the
      # record's on update. An edit that omits an attribute leaves it unchanged, so
      # these decisions have to read the resulting state, not only what was sent.
      def existing_state
        { autonomous_service_account_id: nil, event_types: [], description: nil }
      end

      def system_event_types_changed?(params)
        return false unless params.key?(:event_types)

        system_types = ->(types) { Array(types).map(&:to_i) & ::Ai::FlowTrigger::SYSTEM_EVENT_TYPE_IDS }
        system_types.call(params[:event_types]).sort != system_types.call(existing_state.fetch(:event_types)).sort
      end

      def system_event_types_error
        ServiceResponse.error(
          message: s_('AICatalog|Security policy triggers are managed by security policies ' \
            'and cannot be added or removed'),
          reason: ERROR_REASON_INVALID_TRIGGER
        )
      end

      def autonomous_after_apply?(params)
        event_types = params.key?(:event_types) ? Array(params[:event_types]) : existing_state.fetch(:event_types)

        ::Ai::FlowTrigger.autonomous_only?(event_types)
      end

      # Sets the account in params: its own for an autonomous trigger, nil
      # when an edit drops the autonomous events and falls back to the
      # shared consumer account.
      # Returns the ids the post-commit membership work needs: the dropped one
      # to revoke, and the reused one to re-level.
      def assign_autonomous_service_account(params, ai_catalog_item_consumer)
        return ServiceResponse.success if ai_catalog_item_consumer.blank?

        unless autonomous_after_apply?(params)
          params[:autonomous_service_account_id] = nil

          return ServiceResponse.success(
            payload: { dropped_service_account_id: existing_state.fetch(:autonomous_service_account_id) }
          )
        end

        resolved = resolve_autonomous_service_account(params, ai_catalog_item_consumer)
        return resolved if resolved.error?

        params[:autonomous_service_account_id] = resolved.payload[:service_account_id]

        ServiceResponse.success(
          payload: { reused_service_account_id: resolved.payload[:reused_service_account_id] }
        )
      end

      def resolve_autonomous_service_account(params, ai_catalog_item_consumer)
        existing_service_account_id = existing_state.fetch(:autonomous_service_account_id)

        if existing_service_account_id
          return ServiceResponse.success(
            payload: { service_account_id: existing_service_account_id,
                       reused_service_account_id: existing_service_account_id }
          )
        end

        access_level = ai_catalog_item_consumer.active_service_account_access_level(project)

        # No role to match means the account would
        # join at a guessed role and fail at run time.
        unless access_level
          return ServiceResponse.error(
            message: "The flow's service account is not a member of this project",
            reason: ERROR_REASON_INVALID_TRIGGER
          )
        end

        provisioned = ProvisionAutonomousServiceAccountService.new(
          project: project,
          current_user: current_user,
          item_consumer: ai_catalog_item_consumer,
          description: (params[:description].presence || existing_state.fetch(:description)).to_s,
          access_level: access_level
        ).execute

        return provisioned if provisioned.error?

        ServiceResponse.success(payload: { service_account_id: provisioned.payload[:service_account].id })
      end

      # A scheduled run has no human behind it, so only an editor who could grant the account's role
      # and manage project members may change what it runs.
      def service_account_access_error(access_level, attributes)
        unless project.can_assign_role?(current_user, access_level)
          return unauthorized_change_error(
            s_('AICatalog|%{attributes} cannot be changed on a scheduled automation that runs with more ' \
              'permissions than your own'),
            attributes
          )
        end

        return if Ability.allowed?(current_user, :invite_project_members, project)

        unauthorized_change_error(
          s_('AICatalog|%{attributes} cannot be changed on a scheduled automation unless you can manage the ' \
            'service account it runs as'),
          attributes
        )
      end

      def unauthorized_change_error(message, attributes)
        ServiceResponse.error(
          message: format(message, attributes: human_attribute_names(attributes)),
          reason: ERROR_REASON_INSUFFICIENT_SERVICE_ACCOUNT_ACCESS
        )
      end

      def human_attribute_names(attributes)
        attributes.map { |attribute| ::Ai::FlowTrigger.human_attribute_name(attribute) }.to_sentence
      end

      # A trigger that becomes scheduled gets a new account at the role of the consumer's account.
      def new_service_account_goals_error(params, ai_catalog_item_consumer)
        return if ::Ai::FlowTrigger.normalize_goals(params[:goals]).blank?
        return unless ai_catalog_item_consumer && autonomous_after_apply?(params)

        access_level = ai_catalog_item_consumer.active_service_account_access_level(project)
        return unless access_level

        service_account_access_error(access_level, [:goals])
      end

      def log_flow_schedule_sync_error(trigger, error_message)
        ::Gitlab::AppLogger.error(
          message: 'Failed to sync the flow schedule for the flow trigger',
          flow_trigger_id: trigger.id,
          project_id: trigger.project_id,
          group_id: trigger.group_id,
          error_message: error_message
        )
      end

      # Runs on any edit that keeps an existing dedicated account, whatever the
      # edit changed, so it doubles as opportunistic drift correction.
      #
      # Not fatal: the service logs validation failures itself, anything raised
      # is tracked here, and RunFlowScheduleWorker reconciles again immediately
      # before the account can act.
      def sync_access_level(service_account_id, ai_catalog_item_consumer)
        SyncAutonomousServiceAccountRoleService.new(
          project: project,
          item_consumer: ai_catalog_item_consumer,
          service_account_id: service_account_id,
          current_user: current_user
        ).execute
      rescue StandardError => e
        ::Gitlab::ErrorTracking.track_exception(
          e, project_id: project.id, service_account_id: service_account_id
        )
      end

      # The account keeps no project access once nothing points at it. Triggers
      # may share an account, so only drop membership when none remain. Shared
      # with DestroyService, which reaches the same state by deleting a trigger.
      def revoke_dedicated_account_access(service_account, trigger_project)
        return if service_account.nil?
        return if ::Ai::FlowTrigger.for_autonomous_service_account(service_account, trigger_project).exists?

        begin
          ::Ai::ServiceAccountMemberRemoveService.new(current_user, trigger_project, service_account).execute

          # The remove service reports success unconditionally, so confirm the
          # membership is actually gone rather than trusting the response.
          trigger_project.project_members.reset
          return if trigger_project.member(service_account).nil?
        rescue StandardError => e
          ::Gitlab::ErrorTracking.track_exception(
            e, project_id: trigger_project.id, service_account_id: service_account.id
          )
        end

        ::Gitlab::AppLogger.warn(
          ::Labkit::Fields::LOG_MESSAGE => 'Failed to revoke the dedicated service account project access',
          ::Labkit::Fields::CLASS_NAME => self.class.name,
          ::Labkit::Fields::GL_PROJECT_ID => trigger_project.id,
          'service_account_id' => service_account.id
        )
      end

      def enforce_composite_identity!(service_account)
        return if service_account.nil?

        service_account.update!(
          composite_identity_enforced: true
        )
      end

      # Older custom flows may have invalid configs, so prevent new trigger events for these flows,
      # as the trigger would be guaranteed to result in a DWS failure when it fires.
      def custom_flow_config_error(item_consumer)
        return unless item_consumer&.item&.custom_flow?

        result = Ai::Catalog::Items::ValidateConfigService
          .new(container: container, current_user: current_user)
          .execute(item_consumer.pinned_version&.definition)

        return if result.success?

        return result if result.reason == DuoWorkflow::DuoWorkflowService::Client::ERROR_REASON_SERVICE_UNAVAILABLE

        ServiceResponse.error(
          message: s_('AICatalog|Cannot add trigger events because the custom flow configuration is invalid'),
          reason: DuoWorkflow::DuoWorkflowService::Client::ERROR_REASON_INVALID_FLOW_CONFIG
        )
      end

      # Triggers for "manual" External Agents can only be created by users who can create External Agents.
      # See https://gitlab.com/gitlab-org/gitlab/-/issues/583687.
      def new_external_agents_allowed?
        Feature.enabled?(:ai_catalog_create_third_party_flows, current_user)
      end

      def disallow_new_external_agent_error
        ServiceResponse.error(message: 'You have insufficient permissions', reason: ERROR_REASON_UNAUTHORIZED)
      end

      # Inherited triggers use system attribution with hierarchy provenance.
      def audit_flow_trigger(event_name, trigger)
        return unless trigger

        audit_context = {
          name: event_name,
          author: audit_author,
          scope: trigger.container,
          target: trigger,
          target_details: "#{trigger.description} (ID: #{trigger.id})",
          message: event_name.humanize
        }
        details = (audit_details || {})
          .merge(on_finish_settings_changes(trigger))
          .merge(flow_changes(trigger))
          .merge(schedule_changes(trigger))
          .merge(goals_changes(trigger))
          .merge(active_changes(trigger))
          .merge(service_account_changes(trigger))
          .transform_values { |value| value.is_a?(Hash) ? value.deep_stringify_keys : value }
        audit_context[:additional_details] = details if details.present?

        ::Gitlab::Audit::Auditor.audit(audit_context)

        nil
      end

      # The on-finish settings decide what a trigger writes for the human of a session when the session
      # finishes, so the audit event records their old and new values.
      def on_finish_settings_changes(trigger)
        changes = trigger.previous_changes.slice('status_on_finish', 'ready_merge_requests_on_finish')
        return {} if changes.empty?

        { on_finish_settings: changes.transform_values { |(from, to)| { from: from, to: to } } }
      end

      def flow_changes(trigger)
        return {} if trigger.previous_changes.slice('config_path', 'ai_catalog_item_consumer_id').empty?

        from = flow_descriptor(
          changed_value(trigger, 'config_path', 0),
          changed_value(trigger, 'ai_catalog_item_consumer_id', 0)
        )
        to = flow_descriptor(
          changed_value(trigger, 'config_path', 1),
          changed_value(trigger, 'ai_catalog_item_consumer_id', 1)
        )

        return {} if from == to

        { flow: { from: from, to: to } }
      end

      def changed_value(trigger, column, position)
        changes = trigger.previous_changes

        changes.key?(column) ? changes[column][position] : trigger[column]
      end

      def flow_descriptor(config_path, ai_catalog_item_consumer_id)
        return { type: 'config_path', config_path: config_path } if config_path.present?
        return if ai_catalog_item_consumer_id.blank?

        item = ai_catalog_item_consumer(ai_catalog_item_consumer_id)&.item

        { type: 'ai_catalog_item', ai_catalog_item_consumer_id: ai_catalog_item_consumer_id, name: item&.name }
      end

      def schedule_changes(trigger)
        return {} unless trigger.previous_changes.key?('filter')

        from, to = trigger.previous_changes['filter']
        from_schedule = from['scheduled'] if from.is_a?(Hash)
        to_schedule = to['scheduled'] if to.is_a?(Hash)
        return {} if from_schedule == to_schedule

        { schedule: { from: from_schedule, to: to_schedule } }
      end

      def goals_changes(trigger)
        return {} unless trigger.previous_changes.key?('goals')

        from, to = trigger.previous_changes['goals']
        { goals: { from: from, to: to } }
      end

      def active_changes(trigger)
        return {} unless trigger.previous_changes.key?('active')

        from, to = trigger.previous_changes['active']
        { active: { from: from, to: to } }
      end

      def service_account_changes(trigger)
        return {} unless trigger.previous_changes.keys.intersect?(
          %w[autonomous_service_account_id ai_catalog_item_consumer_id user_id]
        )

        from = effective_account_id(trigger, 0)
        to = effective_account_id(trigger, 1)
        return {} if from == to

        { service_account: { from: account_descriptor(from), to: account_descriptor(to) } }
      end

      def effective_account_id(trigger, position)
        autonomous_account_id = changed_value(trigger, 'autonomous_service_account_id', position)
        return autonomous_account_id if autonomous_account_id.present?

        consumer_id = changed_value(trigger, 'ai_catalog_item_consumer_id', position)
        return ai_catalog_item_consumer(consumer_id)&.active_service_account_id if consumer_id.present?

        changed_value(trigger, 'user_id', position)
      end

      def account_descriptor(user_id)
        return if user_id.blank?

        { id: user_id, username: service_account(user_id)&.username }
      end

      def audit_author
        authorization_context&.audit_author || current_user
      end

      def audit_details
        authorization_context&.audit_details
      end

      def misaligned_service_account_error
        ServiceResponse.error(
          message: s_('AICatalog|The service account does not belong to the configuration for the agent or flow ' \
            'associated with this project'),
          reason: ERROR_REASON_SERVICE_ACCOUNT_MISMATCH
        )
      end

      def service_account_compatible_with_item_consumer?(service_account, ai_catalog_item_consumer)
        return true if service_account.nil? || ai_catalog_item_consumer.nil?

        ai_catalog_item_consumer.active_service_account == service_account
      end
    end
  end
end
