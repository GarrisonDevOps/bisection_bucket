# frozen_string_literal: true

module Organizations
  module Transfer
    class GroupsService
      include Gitlab::Utils::StrongMemoize
      include Organizations::Transfer::Concerns::OrganizationUpdater

      TransferError = Class.new(StandardError)
      BATCH_SIZE = 50
      SLACK_SCOPE_BATCH_LIMIT = 1_000

      # force: re-run a converged transfer to catch up newly-supported tables.
      def initialize(group:, new_organization:, current_user:, force: false)
        @group = group
        @new_organization = new_organization
        @current_user = current_user
        @force = force
      end

      def async_execute
        return error_response_for_rejected_transfer unless can_transfer?

        Organizations::Groups::TransferWorker.perform_async(
          {
            'group_id' => group.id,
            'organization_id' => new_organization.id,
            'current_user_id' => current_user.id,
            'force' => force
          }
        )

        ServiceResponse.success(
          message: s_("TransferOrganization|Group transfer to organization initiated")
        )
      end

      def execute
        return error_response_for_rejected_transfer unless can_transfer?

        capture_log_context
        resolve_source_organization
        persist_transfer_source_organization
        perform_transfer

        publish_post_transfer_side_effects
        mark_transfer_completed

        log_transfer_success
        ServiceResponse.success
      rescue StandardError => e
        Gitlab::ErrorTracking.track_exception(e, **(@log_context || {}))
        log_transfer_error(e.message)
        ServiceResponse.error(message: e.message)
      end

      private

      attr_reader :group, :new_organization, :current_user, :force

      def resolve_source_organization
        old_organization
      end

      # Once the root has moved, group.organization_id is the target, so the source
      # must come from the persisted value.
      def old_organization
        source_id = root_moved_to_target? ? persisted_source_organization_id : group.organization_id

        organization = Organizations::Organization.find_by_id(source_id)
        organization ||= default_organization if force
        organization
      end
      strong_memoize_attr :old_organization

      def root_moved_to_target?
        group.organization_id == new_organization.id
      end

      def persisted_source_organization_id
        group.state_metadata['organization_transfer_source_id']
      end

      # rubocop:disable Gitlab/AvoidDefaultOrganization -- forced catch-up fallback only
      def default_organization
        Organizations::Organization.default_organization
      end
      # rubocop:enable Gitlab/AvoidDefaultOrganization

      def persist_transfer_source_organization
        return if root_moved_to_target?

        group.state_metadata['organization_transfer_source_id'] = group.organization_id
        group.namespace_details.save!
      end

      # The mark is the durable "done" record, so the source is cleared.
      def mark_transfer_completed
        group.state_metadata['organization_transfer_completed_at'] = Time.current.as_json
        group.state_metadata['organization_transfer_completed_organization_id'] = new_organization.id
        group.state_metadata['organization_transfer_source_id'] = nil
        group.namespace_details.save!
      end

      def perform_transfer
        transfer_namespaces_and_projects
        transfer_topics
        transfer_slack_api_scopes
        transfer_infrastructure
      end

      def publish_post_transfer_side_effects
        schedule_pool_repository_disconnections
        schedule_ci_runners_transfer
        schedule_user_agent_details_transfer
        schedule_sync_workers
        publish_event
      end

      # One namespace batch can own thousands of bots, so slice the resolved ids to keep every
      # downstream users IN-list bounded by BATCH_SIZE.
      def transfer_bots(user_ids)
        return unless transfer_bots?

        user_ids.each_slice(BATCH_SIZE) { |slice| transfer_bots_slice(slice) }
      end

      def transfer_bots?
        Feature.enabled?(:organization_transfer_group_bots, group)
      end
      strong_memoize_attr :transfer_bots?

      def transfer_bots_slice(user_ids)
        # Filter after resolving ids: a re-run still resolves already-moved bots from user_details
        # (which has no organization column), so skip when none remain in the source organization.
        bots = bots_in_organization(user_ids)
        return unless bots.exists?

        service = Organizations::Transfer::UsersService.new(
          users: bots,
          new_organization: new_organization
        )
        service.prepare_bots
        result = service.execute

        return unless result.error?

        raise TransferError, result.message, cause: result.payload[:exception]
      end

      # rubocop:disable CodeReuse/ActiveRecord -- used only in this service
      # rubocop:disable Database/AvoidUsingPluckWithoutLimit -- transfer_bots slices the result by BATCH_SIZE
      # Service accounts link via provisioned_by_group_id; resource access token bots link
      # via bot_namespace_id (the group or a project's project_namespace, both in namespace_ids).
      def namespace_owned_bot_ids(namespace_ids)
        UserDetail
          .where(provisioned_by_group_id: namespace_ids)
          .or(UserDetail.where(bot_namespace_id: namespace_ids))
          .pluck(:user_id)
      end
      # rubocop:enable Database/AvoidUsingPluckWithoutLimit
      # rubocop:enable CodeReuse/ActiveRecord

      # rubocop:disable CodeReuse/ActiveRecord -- used only in this service
      # rubocop:disable Database/AvoidUsingPluckWithoutLimit -- transfer_bots slices the result by BATCH_SIZE
      def project_owned_bot_ids(project_ids)
        UserDetail.where(provisioned_by_project_id: project_ids).pluck(:user_id)
      end
      # rubocop:enable Database/AvoidUsingPluckWithoutLimit
      # rubocop:enable CodeReuse/ActiveRecord

      # Resolve candidate user ids from the (bounded, indexed) user_details lookup first, then
      # filter by a concrete id list. Avoids planning the OR-ed subquery against a huge org's users.
      def bots_in_organization(user_ids)
        User.bots.in_organization(old_organization).id_in(user_ids)
      end

      def transfer_namespaces_and_projects
        # `skope: Namespace` ensures we get both Group and ProjectNamespace types
        descendant_ids = group.self_and_descendant_ids(skope: Namespace)
        target_hash_ids_by_source_id = transfer_stage_event_hashes(descendant_ids)

        descendant_ids.in_groups_of(BATCH_SIZE, false) do |batch_ids|
          Namespace.id_in(batch_ids).update_all(
            organization_id: new_organization.id,
            visibility_level: Arel.sql('LEAST(?, visibility_level)', new_organization.visibility_level)
          )
          project_relation = Project.in_namespace(batch_ids)
          project_relation.each_batch(of: BATCH_SIZE) do |batch|
            collect_pool_repository_disconnections(batch)
            batch.update_all(
              organization_id: new_organization.id,
              visibility_level: Arel.sql('LEAST(?, visibility_level)', new_organization.visibility_level)
            )
            transfer_bots(project_owned_bot_ids(batch.ids)) # rubocop:disable CodeReuse/ActiveRecord -- .ids bounded by each_batch
          end

          transfer_fork_networks(project_relation.select(:id))
          transfer_bots(namespace_owned_bot_ids(batch_ids))
          transfer_bulk_import_trackers(batch_ids, project_relation.select(:id))

          transfer_oauth_application_granular_scopes(batch_ids)
          transfer_oauth_applications(batch_ids)
          target_hash_ids_by_source_id.each do |source_hash_id, target_hash_id|
            repoint_stage_events(source_hash_id, target_hash_id, batch_ids)
          end
        end

        # Last, so an interrupted run leaves stages on the source hashes and a re-run finds them again.
        stages = stages_with_event_hashes(descendant_ids)
        target_hash_ids_by_source_id.each do |source_hash_id, target_hash_id|
          repoint_stages(stages, source_hash_id, target_hash_id)
        end
      end

      # rubocop:disable CodeReuse/ActiveRecord -- used only in this service
      def transfer_oauth_application_granular_scopes(namespace_ids)
        application_ids = Authn::OauthApplication
          .owned_by_namespaces(namespace_ids)
          .where(organization_id: old_organization.id)
          .select(:id)

        update_organization_id_for(Authz::OauthApplicationGranularScope) do |relation|
          relation.where(application_id: application_ids)
        end

        granular_scope_ids = Authz::OauthApplicationGranularScope
          .where(application_id: application_ids)
          .select(:granular_scope_id)

        update_organization_id_for(Authz::GranularScope) do |relation|
          relation.where(id: granular_scope_ids)
        end
      end
      # rubocop:enable CodeReuse/ActiveRecord

      def transfer_oauth_applications(namespace_ids)
        update_organization_id_for(Authn::OauthApplication) do |relation|
          relation.owned_by_namespaces(namespace_ids)
        end
      end

      # rubocop:disable CodeReuse/ActiveRecord -- used only in this service
      def transfer_fork_networks(project_ids)
        ForkNetwork.where(root_project_id: project_ids).update_all(organization_id: new_organization.id)
      end
      # rubocop:enable CodeReuse/ActiveRecord

      # rubocop:disable CodeReuse/ActiveRecord -- used only in this service
      # Trackers copy the entity's organization_id at insert, before the import repoints the entity
      # to its new group or project, so they keep it and need moving by entity.
      def transfer_bulk_import_trackers(namespace_ids, project_ids)
        [
          BulkImports::Entity.where(namespace_id: namespace_ids),
          BulkImports::Entity.where(project_id: project_ids)
        ].each do |entities|
          trackers = BulkImports::Tracker.where(bulk_import_entity_id: entities.select(:id))

          update_organization_id_for(BulkImports::Tracker) do |relation|
            relation.where(bulk_import_entity_id: entities.select(:id))
          end

          update_organization_id_for(BulkImports::BatchTracker) do |relation|
            relation.where(tracker_id: trackers.select(:id))
          end
        end
      end
      # rubocop:enable CodeReuse/ActiveRecord

      def transfer_topics
        Organizations::Transfer::TopicsService.new(
          group: group,
          old_organization: old_organization,
          new_organization: new_organization
        ).execute
      end

      # rubocop:disable CodeReuse/ActiveRecord -- scoped queries for duplication transfer
      def transfer_slack_api_scopes
        namespace_ids = group.self_and_descendant_ids(skope: Namespace)

        group_scope_ids = Integrations::SlackWorkspace::IntegrationApiScope
          .where(group_id: namespace_ids)
          .distinct
          .limit(SLACK_SCOPE_BATCH_LIMIT)
          .pluck(:slack_api_scope_id)

        project_scope_ids = Integrations::SlackWorkspace::IntegrationApiScope
          .where(project_id: group.all_projects)
          .distinct
          .limit(SLACK_SCOPE_BATCH_LIMIT)
          .pluck(:slack_api_scope_id)

        all_scope_ids = group_scope_ids | project_scope_ids

        old_scopes = Integrations::SlackWorkspace::ApiScope
          .where(id: all_scope_ids, organization_id: old_organization.id)

        old_scope_names = old_scopes.map(&:name)
        new_scopes = Integrations::SlackWorkspace::ApiScope
          .find_or_initialize_by_names(old_scope_names, organization_id: new_organization.id)

        name_to_new_id = new_scopes.index_by(&:name).transform_values(&:id)

        old_scopes.each do |old_scope|
          new_id = name_to_new_id[old_scope.name]

          Integrations::SlackWorkspace::IntegrationApiScope
            .where(group_id: namespace_ids, slack_api_scope_id: old_scope.id)
            .update_all(slack_api_scope_id: new_id)

          Integrations::SlackWorkspace::IntegrationApiScope
            .where(project_id: group.all_projects, slack_api_scope_id: old_scope.id)
            .update_all(slack_api_scope_id: new_id)
        end
      end
      # rubocop:enable CodeReuse/ActiveRecord

      def transfer_infrastructure
        transfer_burned_project_routes
        transfer_agent_organization_authorizations
      end

      # rubocop:disable CodeReuse/ActiveRecord -- used only in this service
      # Runs once for the whole hierarchy: event group_id is the issuable's parent group, which need not
      # share a namespace batch with the stage that produced the event.
      def transfer_stage_event_hashes(namespace_ids)
        stages = stages_with_event_hashes(namespace_ids)
        target_hash_ids_by_source_id = {}

        Analytics::CycleAnalytics::StageEventHash
          .where(organization_id: old_organization.id)
          .each_batch(of: BATCH_SIZE) do |hash_batch|
            source_hashes = hash_batch.where_exists(matching_stages_scope(stages)).to_a
            next if source_hashes.empty?

            target_ids_by_sha256 = ensure_target_stage_event_hashes(source_hashes)

            source_hashes.each do |source_hash|
              target_hash_ids_by_source_id[source_hash.id] = target_ids_by_sha256.fetch(source_hash.hash_sha256)
            end
          end

        target_hash_ids_by_source_id
      end

      def stages_with_event_hashes(namespace_ids)
        Analytics::CycleAnalytics::Stage
          .where(group_id: namespace_ids)
          .where.not(stage_event_hash_id: nil)
      end

      def matching_stages_scope(stages)
        stages.where(
          Analytics::CycleAnalytics::Stage.arel_table[:stage_event_hash_id]
            .eq(Analytics::CycleAnalytics::StageEventHash.arel_table[:id])
        )
      end

      def ensure_target_stage_event_hashes(source_hashes)
        hash_sha256_values = source_hashes.map(&:hash_sha256)
        attributes = hash_sha256_values.map do |hash_sha256|
          { organization_id: new_organization.id, hash_sha256: hash_sha256 }
        end

        Analytics::CycleAnalytics::StageEventHash.insert_all(
          attributes,
          unique_by: 'index_cycle_analytics_stage_event_hashes_on_org_id_sha_256',
          returning: false
        )

        Analytics::CycleAnalytics::StageEventHash
          .where(organization_id: new_organization.id, hash_sha256: hash_sha256_values)
          .index_by(&:hash_sha256)
          .transform_values(&:id)
      end

      def repoint_stages(stages, source_hash_id, target_hash_id)
        stages.where(stage_event_hash_id: source_hash_id).each_batch(of: BATCH_SIZE) do |stage_batch|
          stage_batch.update_all(stage_event_hash_id: target_hash_id)
        end
      end

      def repoint_stage_events(source_hash_id, target_hash_id, group_ids)
        return if source_hash_id == target_hash_id

        stage_event_models.each do |model|
          source_events = model.where(stage_event_hash_id: source_hash_id, group_id: group_ids)

          # Ordering by the issuable id has no supporting index and times out. Moved rows leave
          # the scope, so an unordered limit loop terminates.
          loop do
            events = source_events.limit(BATCH_SIZE).to_a
            break if events.empty?

            # Aggregation may already have written a target row for the same issuable; keep it.
            model.insert_all(events.map { |event| event.attributes.merge('stage_event_hash_id' => target_hash_id) })
            source_events.where(model.issuable_id_column => events.map { |event| event[model.issuable_id_column] })
              .delete_all
          end
        end
      end

      def stage_event_models
        [
          Analytics::CycleAnalytics::IssueStageEvent,
          Analytics::CycleAnalytics::MergeRequestStageEvent
        ]
      end
      # rubocop:enable CodeReuse/ActiveRecord

      # rubocop:disable CodeReuse/ActiveRecord -- used only in this service
      def transfer_burned_project_routes
        path_prefix = "#{group.full_path.downcase}/"
        like_pattern = "#{Authn::BurnedProjectRoute.sanitize_sql_like(path_prefix)}%"
        path_scope = ->(relation) { relation.where("LOWER(path) LIKE ?", like_pattern) }

        old_burns = path_scope.call(Authn::BurnedProjectRoute.where(organization_id: old_organization.id))
        new_burns = path_scope.call(Authn::BurnedProjectRoute.where(organization_id: new_organization.id))
        occupant_route = Route.where(source_type: Project.name)
          .where("routes.source_id = burned_project_routes.project_id")
          .where("LOWER(routes.path) = LOWER(burned_project_routes.path)")

        # The unique index keeps one burn per path, and a burn does not block the project it
        # names. Keep the source-org burn when it names the project now at the path, so that
        # project's ID-token builds keep working. Otherwise the target-org burn wins.
        new_burns.where("LOWER(path) IN (?)", old_burns.where_exists(occupant_route).select("LOWER(path)"))
          .where_not_exists(occupant_route)
          .each_batch(of: ORGANIZATION_ID_UPDATE_BATCH_SIZE) { |batch| batch.delete_all }

        old_burns.where("LOWER(path) IN (?)", new_burns.select("LOWER(path)"))
          .each_batch(of: ORGANIZATION_ID_UPDATE_BATCH_SIZE) { |batch| batch.delete_all }

        update_organization_id_for(Authn::BurnedProjectRoute, &path_scope)
      end
      # rubocop:enable CodeReuse/ActiveRecord

      # rubocop:disable CodeReuse/ActiveRecord -- used only in this service
      def transfer_agent_organization_authorizations
        descendant_agents = Clusters::Agent
          .joins(project: :namespace)
          .where("namespaces.traversal_ids @> '{?}'", group.id)
          .where("cluster_agents.id = agent_organization_authorizations.agent_id")

        update_organization_id_for(
          Clusters::Agents::Authorizations::CiAccess::OrganizationAuthorization
        ) do |relation|
          relation.where_exists(descendant_agents)
        end
      end
      # rubocop:enable CodeReuse/ActiveRecord

      def projects
        Project.in_namespace(group.self_and_descendant_ids(skope: Namespace))
      end
      strong_memoize_attr :projects

      # rubocop:disable CodeReuse/ActiveRecord -- used only in this service
      def collect_pool_repository_disconnections(batch)
        # rubocop:disable Database/AvoidUsingPluckWithoutLimit -- bounded by each_batch
        pool_repository_project_ids.concat(batch.where.not(pool_repository_id: nil).pluck(:id))
        # rubocop:enable Database/AvoidUsingPluckWithoutLimit
      end
      # rubocop:enable CodeReuse/ActiveRecord

      def pool_repository_project_ids
        @pool_repository_project_ids ||= []
      end

      def schedule_pool_repository_disconnections
        pool_repository_project_ids.each do |project_id|
          Repositories::LeavePoolRepositoryWorker.perform_async(project_id)
        end
      end

      # Publish once for the root group only. Descendants implicitly move with it.
      # Subscribers that need to act on descendant projects must traverse them
      # independently (e.g. via NamespaceEachBatch).
      def publish_event
        Gitlab::EventStore.publish(
          Organizations::GroupTransferredEvent.new(data: {
            group_id: group.id,
            old_organization_id: old_organization.id,
            new_organization_id: new_organization.id
          })
        )
      end

      def schedule_ci_runners_transfer
        ::Ci::Runners::TransferOrganizationWorker.perform_async(group.id, old_organization.id, new_organization.id)
      end

      def schedule_user_agent_details_transfer
        ::Organizations::TransferUserAgentDetailsWorker.perform_async(
          group.id, old_organization.id, new_organization.id
        )
      end

      def schedule_sync_workers
        ::Namespaces::SyncEvent.enqueue_worker
        ::Projects::SyncEvent.enqueue_worker
      end

      def log_transfer_success
        log_transfer
      end

      def log_transfer_error(error_message)
        log_transfer(error_message)
      end

      def capture_log_context
        @log_context = {
          group_path: group.full_path,
          group_id: group.id,
          new_organization_path: new_organization&.full_path,
          new_organization_id: new_organization&.id
        }
      end

      def log_transfer(error_message = nil)
        action = error_message.nil? ? "was" : "was not"

        log_payload = (@log_context || {}).merge(
          message: "Group #{action} transferred to a new organization",
          error_message: error_message
        )

        if error_message.nil?
          ::Gitlab::AppLogger.info(log_payload)
        else
          ::Gitlab::AppLogger.error(log_payload)
        end
      end

      def can_transfer?
        return true if group_is_root? && !already_transferred? && has_permission? && source_resolvable?

        false
      end

      def error_response_for_rejected_transfer
        reason = transfer_error_reason
        message = transfer_error

        # An unresolvable source means the persisted transfer state is inconsistent and
        # needs a manual fix, unlike ordinary rejections, so surface it for triage.
        if reason == :unresolved_source
          capture_log_context
          log_transfer_error(message)
          Gitlab::ErrorTracking.track_exception(TransferError.new(message), **(@log_context || {}))
        end

        ServiceResponse.error(message: message, reason: reason)
      end

      def transfer_error
        format(
          s_("TransferOrganization|Group organization transfer failed: %{error_message}"),
          error_message: localized_error_messages.fetch(transfer_error_reason)
        )
      end

      # Guards are checked in order and the first failure wins, so a later guard's inputs
      # (e.g. new_organization in source_resolvable?) are not evaluated once an earlier
      # one fails.
      def transfer_error_reason
        return :group_not_root unless group_is_root?
        return :already_transferred if already_transferred?
        return :missing_permission unless has_permission?

        # Reached only when the earlier guards pass, so the remaining rejection
        # can_transfer? found is an unresolvable source.
        :unresolved_source
      end

      def group_is_root?
        !group.has_parent?
      end

      # Memoized because only the up-front guards call it, before perform_transfer
      # changes the source. Rejects a source equal to the target, which would otherwise
      # raise mid-transfer when a forced catch-up falls back to the default organization.
      def source_resolvable?
        source = old_organization
        source.present? && source.id != new_organization.id
      end
      strong_memoize_attr :source_resolvable?

      # Done when a prior run marked completion, or the group is on the target with no
      # recorded source (never ours to transfer). Absent that, assume incomplete.
      def already_transferred?
        return false unless new_organization
        return false if force
        return true if completed_for_target?

        group.organization_id == new_organization.id &&
          group.state_metadata['organization_transfer_source_id'].nil?
      end
      strong_memoize_attr :already_transferred?

      def completed_for_target?
        group.state_metadata['organization_transfer_completed_organization_id'] == new_organization.id
      end

      def has_permission?
        return false unless Ability.allowed?(current_user, :admin_group, group)
        return false unless Ability.allowed?(current_user, :update_organization, new_organization)

        true
      end

      def localized_error_messages
        {
          group_not_root: s_(
            'TransferOrganization|Only top-level groups can be transferred to a different organization.'
          ),
          already_transferred: s_('TransferOrganization|Group is already in the target organization.'),
          missing_permission: s_("TransferOrganization|You must be an owner of both the group and new organization."),
          unresolved_source: s_('TransferOrganization|The source organization could not be determined.')
        }.freeze
      end
    end
  end
end

Organizations::Transfer::GroupsService.prepend_mod
