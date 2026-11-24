# frozen_string_literal: true

module Ai
  module Catalog
    module ItemConsumers
      class CreateService < ::BaseContainerService
        include EventsTracking

        MAX_SERVICE_NAME_LENGTH = 90
        SERVICE_ACCOUNT_ACCESS_LEVEL = ::Gitlab::Access::DEVELOPER

        def initialize(container:, current_user: nil, params: {}, authorization_context: nil)
          super(container: container, current_user: current_user, params: params)

          @authorization_context = authorization_context
          validate_authorization_context!
        end

        def execute
          # When creating a project-level item consumer, a parent group-level item consumer is required.
          # If one is not explicitly provided, we attempt to auto-resolve it by looking for an existing
          # group item consumer or creating one by recursively calling this service with the project's
          # top-level group as the container.
          #
          # Since the user may not have permissions on the top-level group directly, we pass
          # `authorization_container` set to the project, so authorization is checked against
          # the project rather than the group.
          if should_auto_resolve_parent_item_consumer?
            resolve_result = auto_resolve_parent_item_consumer
            return resolve_result if resolve_result.error?

            params[:parent_item_consumer] = resolve_result.payload[:item_consumer]
          end

          return validation_error if validation_error

          add_service_account_result = create_service_account_result = create_item_consumer_result = nil
          project_member = item_consumer = service_account_response = nil

          ApplicationRecord.transaction do
            existing_group_direct_consumer.destroy! if replace_direct_group_consumer_with_inheritance?

            create_service_account_result, service_account_response = create_service_account
            raise ActiveRecord::Rollback if create_service_account_result == :failure

            create_item_consumer_result, item_consumer = create_item_consumer(service_account_response)
            raise ActiveRecord::Rollback if create_item_consumer_result == :failure

            add_service_account_result, project_member = add_service_account_to_project
            raise ActiveRecord::Rollback if add_service_account_result == :failure
          end

          return error(service_account_response) if create_service_account_result == :failure
          return error_creating(project_member) if add_service_account_result == :failure
          return error_creating(item_consumer) if create_item_consumer_result == :failure

          track_item_consumer_event(item_consumer, 'create_ai_catalog_item_consumer', item_consumer.flow_trigger)
          send_audit_events(
            item_consumer,
            audit_event_name,
            author: audit_author,
            additional_details: audit_details
          )
          audit_inherited_membership(add_service_account_result, project_member)
          sync_flow_schedules(item_consumer)
          add_service_account_to_inherited_projects(item_consumer)
          audit_provisioned_service_account(item_consumer, service_account_response, create_service_account_result)
          audit_provisioned_service_account(item_consumer, @autonomous_service_account, :success)

          ServiceResponse.success(payload: { item_consumer: item_consumer, warnings: Array(@warnings) })
        end

        private

        attr_reader :authorization_context

        strong_memoize_attr def validation_error
          return error_not_project_or_top_level_group unless for_project_or_top_level_group?
          return error_project_must_belong_to_a_group if project_container? && !top_level_group.is_a?(Group)

          inheritance_error = inheritance_validation_error
          return inheritance_error if inheritance_error

          provisioning_error = project_provisioning_authorization_validation_error
          return provisioning_error if provisioning_error

          return error_parent_item_consumer_not_passed if project_item_without_parent_item_consumer?
          return error_version_not_released if requested_version_invalid?
          return error_no_pinned_version_prefix if pinned_version_prefix.nil? && !nil_version_pin_enforced?
          return error_foundational_flow_triggers_not_allowed if foundational_flow_with_user_triggers?

          error_flow_triggers_not_allowed if flow_triggers_not_allowed?
        end

        def inheritance_validation_error
          return error_inheritance_feature_disabled if inheritance_kind? && !inheritance_feature_enabled?
          return error_foundational_flow_inheritance_not_supported if inheritance_kind? && item.foundational_flow?

          if replace_direct_group_consumer_with_inheritance? && params[:replace_existing_direct_configurations] != true
            return error_replace_existing_direct_configurations_not_confirmed
          end

          error_already_inherited_from_group if already_inherited_from_group?
        end

        def project_provisioning_authorization_validation_error
          if inherited_project_provisioning?
            failure_reason = authorization_context.item_consumer_failure_reason(
              container: container,
              item: item,
              parent_consumer: parent_item_consumer
            )
            return error_inherited_authorization(failure_reason) if failure_reason
          else
            return error_no_permissions unless allowed?
            return error_foundational_flow_not_in_allowlist if foundational_flow_not_in_allowlist?
          end

          nil
        end

        def audit_event_name
          "enable_ai_catalog_#{item.item_type}"
        end

        def parent_item_consumer_service_account
          parent_item_consumer&.service_account
        end

        def parent_item_consumer
          params[:parent_item_consumer]
        end

        def requires_parent_item_consumer?
          project.present?
        end

        def nil_version_pin_enforced?
          container.is_a?(Project) && item.project_id.present? && container.id == item.project_id
        end
        strong_memoize_attr :nil_version_pin_enforced?

        def project_item_without_parent_item_consumer?
          requires_parent_item_consumer? && parent_item_consumer.nil?
        end

        def flow_triggers_not_allowed?
          # trigger_goals is listed so a goal sent here is refused, not dropped in silence.
          return unless params[:trigger_types] || params[:trigger_filter] || params[:trigger_goals]

          group_container? && !inheritance_kind?
        end

        def foundational_flow_not_in_allowlist?
          return false unless item.foundational_flow?

          container.enabled_flow_catalog_item_ids.exclude?(item.id)
        end

        def foundational_flow_with_user_triggers?
          item.foundational_flow? && params[:trigger_types].present?
        end

        def create_item_consumer(service_account)
          return [:success, @healed_consumer] if @healed_consumer

          # The enabled setting is not currently used, so always set new records as enabled.
          # https://gitlab.com/gitlab-org/gitlab/-/issues/553912#note_2706802395
          params.merge!(
            project: project,
            group: group,
            service_account: service_account,
            enabled: true,
            pinned_version_prefix: pinned_version_prefix
          )
          prepare_trigger_params

          item_consumer_params = params.except(
            :authorization_container, :pinned_version, :replace_existing_direct_configurations
          )
          item_consumer = ::Ai::Catalog::ItemConsumer.new(item_consumer_params)
          # Built before saving so the nested trigger exists and can be handed its
          # own account.
          # On a provisioning refusal, we drop the trigger and keep
          # the consumer unless the account already exists
          # and only its membership failed
          return [:failure, item_consumer] unless provision_autonomous_service_account(item_consumer)
          return [:success, item_consumer] if item_consumer.save

          [:failure, item_consumer]
        end

        def create_service_account
          # In case we don't need to create the service account (because this is not group level), we should return
          # no_op, and continue creating the item consumer.
          return [:no_op, nil] if group.nil? || !(item.flow? || item.third_party_flow?)

          # Creating a group inheritance consumer when the group has an existing direct consumer
          # reuses the direct record's service account
          if replace_direct_group_consumer_with_inheritance? && existing_group_direct_consumer.service_account
            return [:no_op, existing_group_direct_consumer.service_account]
          end

          orphan_consumer = find_orphan_group_consumer
          if orphan_consumer
            response = provision_service_account
            if response.error?
              log_error(
                "Failed to create service account with name '#{service_account_username}': #{response.message}"
              )
              return [:failure, response.message]
            end

            new_service_account = response.payload[:user]
            unless orphan_consumer.update(service_account: new_service_account)
              return [:failure, orphan_consumer.errors.full_messages]
            end

            @healed_consumer = orphan_consumer
            return [:success, new_service_account]
          end

          existing_service_account = group.service_accounts.find_by_username(service_account_username)

          if existing_service_account.present? &&
              Ai::Catalog::ItemConsumer.for_service_account(existing_service_account).none?
            return [:no_op, existing_service_account]
          end

          response = provision_service_account

          if response.error?
            log_error("Failed to create service account with name '#{service_account_username}': #{response.message}")
            return [:failure, response.message]
          end

          [:success, response.payload[:user]]
        end

        def find_orphan_group_consumer
          return unless item.flow? || item.third_party_flow?
          return if inheritance_kind?

          # Scoped to (group_id, ai_catalog_item_id) and filtered to direct records, which is
          # unique per the validate_item_uniqueness validator, so this matches
          # at most one row. Both the group and item columns are indexed (index_ai_catalog_item_consumers_on_group_id
          # and index_ai_catalog_item_consumers_on_ai_catalog_item_id), so the planner
          # can resolve the predicate from a tiny seek without scanning service_account_id.
          # rubocop:disable CodeReuse/ActiveRecord -- narrow self-heal query scoped to group + item + direct kind
          group.configured_ai_catalog_items
            .for_item(item.id)
            .direct
            .where(service_account_id: nil)
            .first
          # rubocop:enable CodeReuse/ActiveRecord
        end

        def provision_service_account
          ::Namespaces::ServiceAccounts::GroupCreateService.new(
            current_user,
            service_account_params,
            uniquify_provided_username: true
          ).execute
        end

        def service_account_params
          {
            namespace_id: group.id,
            name: service_account_name,
            username: service_account_username,
            avatar: service_account_avatar,
            organization_id: group.organization_id,
            composite_identity_enforced: true,
            skip_ai_prefix_validation: true,
            skip_owner_check: true
          }
        end
        strong_memoize_attr :service_account_params

        # Returns the operation so inherited membership audits distinguish creates and updates.
        def add_service_account_to_project
          return [:no_op, nil] unless project_container? && (item.flow? || item.third_party_flow?)

          return [:no_op, nil] if project.team.member?(
            parent_item_consumer_service_account, SERVICE_ACCOUNT_ACCESS_LEVEL
          )

          project_member = project.team.add_member(
            parent_item_consumer_service_account, SERVICE_ACCOUNT_ACCESS_LEVEL,
            current_user: membership_creator, skip_authorization: true,
            immediately_sync_authorizations: sync_authorizations_immediately?
          )

          unless project_member.present? && project_member.persisted? && project_member.errors.empty?
            return [:failure, project_member.presence]
          end

          # The membership check above runs before the row exists, and SafeRequestLoader caches that
          # miss as NO_ACCESS for the rest of the request. Those same callers would otherwise read
          # the stale 0 and fail their permission checks.
          # See https://gitlab.com/gitlab-org/gitlab/-/merge_requests/254154
          project.team.purge_member_access_cache_for_user_id(parent_item_consumer_service_account.id)

          return [:created, project_member] if project_member.previously_new_record?
          return [:updated, project_member] if project_member.saved_change_to_access_level?

          [:no_op, nil]
        end

        # The Duo workspace project is created and then used within the same request from
        # ee/app/services/ee/integrations/slack_events/app_mentioned_service.rb
        def sync_authorizations_immediately?
          project.path == ::Ai::Messaging::WorkspaceProjectService::PROJECT_PATH
        end

        def prepare_trigger_params
          # Deleted first: a key that survives the early returns below reaches
          # ItemConsumer.new, which has no such attribute.
          trigger_types = params.delete(:trigger_types)
          trigger_filter = params.delete(:trigger_filter)
          trigger_goals = params.delete(:trigger_goals)

          return if group_container? && !inheritance_kind?
          return if inherited_project_provisioning?

          if item.foundational_flow?
            flow_definition = ::Ai::Catalog::FoundationalFlow[item.foundational_flow_reference]
            return unless flow_definition&.triggers&.any?

            trigger_types = flow_definition.triggers
            # Default to the flow's default_trigger_filter when the caller passes none,
            # as SyncFoundationalFlowsService#build_trigger_params does.
            trigger_filter ||= flow_definition.default_trigger_filter
          else
            return if trigger_types.nil?

            trigger_types = trigger_types.map { |type| ::Ai::FlowTrigger::EVENT_TYPES[type.to_sym] }
          end

          params[:flow_trigger_attributes] = {
            project: project,
            group: group,
            description: trigger_description,
            event_types: trigger_types,
            filter: trigger_filter || {},
            goals: trigger_goals || {}
          }
        end

        def trigger_description
          "Auto-created triggers for #{item.name}"
        end

        # add_service_account_to_project runs later in this transaction and sets the shared
        # account to the default only when it currently sits below it, leaving a higher role
        # alone -- so the role it ends up holding is max(current, default), not the default.
        # The dedicated account has to match that, not the role held right now.
        def shared_account_access_level_after_grant(item_consumer)
          [
            item_consumer.active_service_account_access_level(project),
            SERVICE_ACCOUNT_ACCESS_LEVEL
          ].compact.max
        end

        def add_service_account_to_inherited_projects(item_consumer)
          return unless item_consumer.inheritance? && item_consumer.service_account_id

          user_id = current_user.id

          item_consumer.run_after_commit_or_now do
            ::Ai::Catalog::AddInheritedServiceAccountMembersToHierarchyWorker.perform_async(user_id, id)
          end
        end

        def sync_flow_schedules(item_consumer)
          sync_result = ::Ai::FlowSchedules::SyncFromTriggerService.new(trigger: item_consumer.flow_trigger).execute
          return unless sync_result.error?

          log_error("Failed to sync flow schedule for item consumer #{item_consumer.id}: #{sync_result.message}")
        end

        def audit_provisioned_service_account(item_consumer, service_account, result)
          return unless result == :success
          return if service_account.nil?

          ServiceAccountProvisionedAuditor.new(
            current_user: current_user,
            service_account: service_account,
            item: item,
            item_consumer: item_consumer
          ).audit
        end

        # A scheduled automation cannot use the consumer's shared account: that one
        # has composite identity enforced, which an unattended run cannot use.
        #
        # Returns true when the enablement may continue, false when it must roll back.
        #
        # A refusal that created nothing drops the trigger rather than the enablement:
        # the consumer and its shared account are usable without it. Keeping the trigger
        # inactive is not an option, since an autonomous one requires an account
        # (Ai::FlowTrigger validation). A failure after the account exists has to roll
        # back otherwise the account outlives the trigger it was created, for with
        # nothing left pointing at it.
        def provision_autonomous_service_account(item_consumer)
          trigger = item_consumer.flow_trigger
          return true unless trigger&.autonomous_only?

          if project.nil?
            item_consumer.errors.add(:base, _('Scheduled automations are not supported for group configurations'))

            return false
          end

          response = ::Ai::FlowTriggers::ProvisionAutonomousServiceAccountService.new(
            project: project,
            current_user: current_user,
            item_consumer: item_consumer,
            description: trigger_description,
            access_level: shared_account_access_level_after_grant(item_consumer),
            audit: false
          ).execute

          if response.error?
            log_error("Failed to provision an autonomous service account for item #{item.id}: #{response.message}")

            if response.reason == ::Ai::FlowTriggers::ProvisionAutonomousServiceAccountService::
              ERROR_REASON_MEMBERSHIP_FAILED
              item_consumer.errors.add(:base, response.message)

              return false
            end

            @warnings = ["The scheduled automation was not created. #{response.message}"]
            item_consumer.flow_trigger = nil

            return true
          end

          @autonomous_service_account = response.payload[:service_account]
          trigger.autonomous_service_account = @autonomous_service_account

          true
        end

        def service_account_name
          name = item.name
          name = "Duo #{name}" if item.foundational_flow_reference.present?

          name[0, MAX_SERVICE_NAME_LENGTH]
        end

        def service_account_username
          prefix = item.foundational_flow_reference.present? ? "duo" : "ai"
          "#{prefix}-#{item.name}-#{group.name}".parameterize
        end

        def service_account_avatar
          Ai::Avatars::LoadService.new(item).execute
        end

        def for_project_or_top_level_group?
          project || group&.root?
        end

        def inheritance_kind?
          params[:kind].to_s == 'inheritance'
        end

        def inheritance_feature_enabled?
          Feature.enabled?(:ai_catalog_group_inherited_consumers, top_level_group)
        end

        def already_inherited_from_group?
          return false unless project_container?
          return false unless inheritance_feature_enabled?

          top_level_group.configured_ai_catalog_items.for_item(item.id).inheritance.exists?
        end

        def existing_group_direct_consumer
          group.configured_ai_catalog_items.for_item(item.id).direct.first
        end
        strong_memoize_attr :existing_group_direct_consumer

        def replace_direct_group_consumer_with_inheritance?
          inheritance_kind? && group_container? && existing_group_direct_consumer.present?
        end

        def top_level_group
          container.root_ancestor
        end

        def item
          params[:item]
        end

        def pinned_version_prefix
          return if nil_version_pin_enforced?

          return resolved_requested_version.version if resolved_requested_version&.released?

          latest_released_version = item.latest_released_version

          return latest_released_version.version if latest_released_version

          # TODO: Remove the below when we can rely on all items having a `latest_released_version`
          # after the data migration of https://gitlab.com/gitlab-org/gitlab/-/issues/572145
          latest_released_version = item.versions.where.not(release_date: nil).order(id: :desc).take # rubocop:disable CodeReuse/ActiveRecord -- Can be removed after https://gitlab.com/gitlab-org/gitlab/-/issues/572145
          latest_released_version&.version
        end
        strong_memoize_attr :pinned_version_prefix

        def resolved_requested_version
          return unless params[:pinned_version]

          item.resolve_version(params[:pinned_version], track_missing: false)
        end
        strong_memoize_attr :resolved_requested_version

        def requested_version_invalid?
          params[:pinned_version].present? && !resolved_requested_version&.released?
        end

        def error_creating(record)
          return error('Failed to enable agent or flow') if record.nil?

          messages = record.errors.full_messages.presence || ['Failed to enable agent or flow']

          if already_configured_error?(record)
            return ServiceResponse.error(message: messages, reason: :already_configured)
          end

          error(messages)
        end

        def already_configured_error?(record)
          record.errors.of_kind?(:base, _('Agent or flow already enabled')) ||
            record.errors.of_kind?(
              :base, s_('AICatalog|An agent or flow can only be enabled once per group or project')
            )
        end

        # Inherited calls must use the existing root-group consumer from their trusted context.
        def should_auto_resolve_parent_item_consumer?
          return false if inherited_project_provisioning?

          requires_parent_item_consumer? &&
            params[:parent_item_consumer].nil?
        end

        def auto_resolve_parent_item_consumer
          return error_project_must_belong_to_a_group unless top_level_group.is_a?(Group)
          return error_already_inherited_from_group if already_inherited_from_group?

          existing = top_level_group.configured_ai_catalog_items.direct.for_item(item).first
          return ServiceResponse.success(payload: { item_consumer: existing }) if existing && !orphan?(existing)

          self.class.new(
            container: top_level_group,
            current_user: current_user,
            params: { item: item, authorization_container: project, kind: :direct }
          ).execute
        end

        def orphan?(consumer)
          (item.flow? || item.third_party_flow?) && consumer.service_account_id.nil?
        end

        def allowed?
          auth_container = params[:authorization_container] || container

          if item.custom_agent? && !Ability.allowed?(current_user, :create_ai_catalog_agent_item_consumer,
            auth_container)
            return false
          end

          if item.flow?
            if item.foundational_flow?
              return false unless Ability.allowed?(current_user, :create_ai_foundational_flow_item_consumer,
                auth_container)
            else
              return false unless Ability.allowed?(current_user, :create_ai_catalog_flow_item_consumer, auth_container)
            end
          end

          if item.third_party_flow? &&
              !Ability.allowed?(current_user, :create_ai_catalog_third_party_flow_item_consumer, auth_container)
            return false
          end

          if item.skill? && !Ability.allowed?(current_user, :create_ai_catalog_skill_item_consumer, auth_container)
            return false
          end

          Ability.allowed?(current_user, :create_ai_catalog_item_consumer, auth_container) &&
            Ability.allowed?(current_user, :read_ai_catalog_item, item)
        end

        def validate_authorization_context!
          return if authorization_context.nil?
          return if authorization_context.is_a?(::Ai::Catalog::Flows::InheritedProjectAuthorization)

          raise ArgumentError, 'Invalid inherited foundational-flow authorization context'
        end

        def inherited_project_provisioning?
          authorization_context.is_a?(::Ai::Catalog::Flows::InheritedProjectAuthorization)
        end

        # Do not attribute the automated membership write to an unauthorized initiator.
        def membership_creator
          return if inherited_project_provisioning?

          current_user
        end

        def audit_author
          authorization_context&.audit_author || current_user
        end

        def audit_details
          authorization_context&.audit_details
        end

        # Normal calls and no-op retries retain their existing audit behavior.
        def audit_inherited_membership(operation, project_member)
          return unless inherited_project_provisioning? && project_member

          event = inherited_membership_audit_event(operation, project_member)
          return unless event

          ::Gitlab::Audit::Auditor.audit(
            name: event[:name],
            author: audit_author,
            scope: project_member.source,
            target: project_member.user,
            target_details: project_member.user.name,
            message: event[:message],
            additional_details: audit_details.merge(event[:details]).merge(
              as: project_member.human_access_labeled,
              member_id: project_member.id,
              member_role_id: project_member.member_role_id
            )
          )

          nil
        end

        def inherited_membership_audit_event(operation, project_member)
          case operation
          when :created
            {
              name: 'member_created',
              message: 'Membership created for inherited foundational-flow provisioning',
              details: { add: 'user_access' }
            }
          when :updated
            {
              name: 'member_updated',
              message: 'Membership updated for inherited foundational-flow provisioning',
              details: {
                change: 'access_level',
                from: membership_access_before_last_save(project_member),
                to: project_member.human_access_labeled,
                expiry_from: project_member.expires_at_before_last_save,
                expiry_to: project_member.expires_at
              }
            }
          end
        end

        def membership_access_before_last_save(project_member)
          project_member.dup.tap do |previous_member|
            previous_member.access_level = project_member.access_level_before_last_save
          end.human_access_labeled
        end

        def error(message, reason: nil)
          ServiceResponse.error(message: Array(message), reason: reason)
        end

        def error_no_permissions
          error("You don't have permission to enable this item, or it doesn't exist")
        end

        def error_inherited_authorization(reason)
          ServiceResponse.error(
            message: ["You don't have permission to enable this item, or it doesn't exist"],
            reason: reason
          )
        end

        def error_flow_triggers_not_allowed
          error("Triggers can't be added when turning on an agent or flow directly for a group")
        end

        def error_foundational_flow_not_in_allowlist
          error("Foundational flow is not allowed by the top-level group settings")
        end

        def error_foundational_flow_triggers_not_allowed
          error("You can't create triggers for foundational flows")
        end

        def error_parent_item_consumer_not_passed
          error("Enable this agent or flow in the top-level group first")
        end

        def error_not_project_or_top_level_group
          error('This agent or flow can only be enabled in projects or top-level groups')
        end

        def error_inheritance_feature_disabled
          error('Turning on agents and flows for a group and all its subgroups is not available')
        end

        def error_already_inherited_from_group
          error("This agent or flow is already inherited from the group and can't be enabled separately",
            reason: :already_inherited)
        end

        def error_replace_existing_direct_configurations_not_confirmed
          error('Inheritance replaces the existing group configuration ' \
            'and any project configurations for this item. Confirm the replacement to continue.')
        end

        def error_no_pinned_version_prefix
          if requires_parent_item_consumer?
            error('This agent or flow must be pinned to a version in the top-level group')
          else
            error('Agent or flow has no latest released version to pin to')
          end
        end

        def error_version_not_released
          error('Pinned version must resolve to a released version of the agent or flow')
        end

        # Foundational flow inheritance is handled separately in
        # https://gitlab.com/gitlab-org/gitlab/-/work_items/627525
        def error_foundational_flow_inheritance_not_supported
          error("Foundational flows can't be turned on using group inheritance")
        end

        def error_project_must_belong_to_a_group
          error('Project must belong to a group')
        end
      end
    end
  end
end
