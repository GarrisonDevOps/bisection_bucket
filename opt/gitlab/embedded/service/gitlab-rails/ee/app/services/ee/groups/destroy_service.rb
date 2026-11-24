# frozen_string_literal: true

module EE
  module Groups
    module DestroyService
      extend ::Gitlab::Utils::Override

      override :async_execute
      def async_execute
        result = super
        log_permanent_deletion_requested_audit_event unless result == ::Groups::DestroyService::UnauthorizedError
        result
      end

      override :execute
      def execute
        with_scheduling_epic_cache_update do
          result = super
          next result if result.error?

          after_destroy(result[:group])
          result
        end
      end

      # Secrets manager cleanup is driven by the database. The FK on
      # `group_secrets_managers.group_id` is `ON DELETE CASCADE`, so
      # destroying the group also deletes the SM row, which fires the
      # `enqueue_gsm_deprovision_task_after_delete` trigger and inserts
      # a deprovision maintenance task with the snapshot ids read off
      # the SM's denormalized columns. The cron worker picks it up and
      # tears down OpenBao asynchronously. See gitlab-org/gitlab#600290.
      # Child groups and projects each fire their own destroy hook,
      # which triggers the same way.

      # Wraps unsafe_execute, not execute/after_destroy, since it's the
      # only entry point every destroy path goes through: direct calls
      # from Users::DestroyService, and CE's own subgroup recursion.
      override :unsafe_execute
      def unsafe_execute
        destroyed_group = group

        super.tap do
          # Skip if destroy didn't commit - a later before_destroy
          # callback may have aborted it, rolling back the reassignment
          # even though the ivar still holds "reassigned" rule objects.
          next unless destroyed_group.destroyed?

          reassigned_rules = destroyed_group.reassigned_protected_environment_approval_rules
          if reassigned_rules.present?
            log_protected_environment_reassignment_audit_events(destroyed_group,
              reassigned_rules)
          end
        end
      end

      private

      override :before_group_destroy
      def before_group_destroy
        super

        ::Workforce::Hierarchy.delete_for_tenant(group: group)
        refresh_blocking_issues_count_after_destroy
      end

      # The group's work items and their links are removed by ON DELETE
      # CASCADE foreign keys, which run no callback, so the work items outside
      # the group that block them are read now and recounted by workers
      # enqueued after the commit, where a failure cannot stop the deletion.
      def refresh_blocking_issues_count_after_destroy
        blocking_ids = ::WorkItems::RelatedWorkItemLink.blocking_ids_outside_namespace(group)
        return if blocking_ids.empty?

        group.run_after_commit do
          # rubocop:disable Scalability/BulkPerformWithContext -- the jobs inherit the context of the group deletion
          ::WorkItems::UpdateBlockingIssuesCountWorker.bulk_perform_async(
            blocking_ids.each_slice(::WorkItems::UpdateBlockingIssuesCountWorker::BATCH_SIZE).map { |ids| [ids] }
          )
          # rubocop:enable Scalability/BulkPerformWithContext
        end
      end

      # rubocop:disable CodeReuse/ActiveRecord
      def users_to_destroy
        group.service_accounts.pluck(:user_id) + super
      end
      # rubocop:enable CodeReuse/ActiveRecord

      def after_destroy(group)
        delete_dependency_proxy_blobs(group)

        return if group&.persisted?

        log_audit_event

        return unless ::Gitlab::Geo.primary? && group.group_wiki_repository

        group.group_wiki_repository.geo_handle_after_destroy
      end

      # rubocop:disable Scalability/BulkPerformWithContext
      def with_scheduling_epic_cache_update
        ids = group.parent_epic_ids_in_ancestor_groups

        group = yield

        ::Epics::UpdateCachedMetadataWorker.bulk_perform_in(
          1.minute,
          ids.each_slice(::Epics::UpdateCachedMetadataWorker::BATCH_SIZE).map { |ids| [ids] }
        )

        group
      end
      # rubocop:enable Scalability/BulkPerformWithContext

      def delete_dependency_proxy_blobs(group)
        # the blobs reference files that need to be destroyed that cascade delete
        # does not remove
        group.dependency_proxy_blobs.destroy_all # rubocop:disable Cop/DestroyAll
      end

      def log_permanent_deletion_requested_audit_event
        audit_context = {
          name: 'group_permanent_deletion_requested',
          author: current_user,
          scope: group.root_ancestor,
          target: group,
          message: 'Group permanent deletion requested',
          target_details: group.full_path,
          additional_details: {
            remove: 'group'
          }
        }

        ::Gitlab::Audit::Auditor.audit(audit_context)
      end

      def log_audit_event
        audit_context = {
          name: 'group_destroyed',
          author: current_user,
          scope: group.root_ancestor,
          target: group,
          message: 'Group destroyed',
          target_details: group.full_path,
          additional_details: {
            remove: 'group'
          }
        }

        ::Gitlab::Audit::Auditor.audit(audit_context)
      end

      # One audit event per reassigned rule. destroyed_group.full_path
      # and .id still resolve here - destroy leaves attribute values and
      # cached associations intact, it just freezes the record.
      def log_protected_environment_reassignment_audit_events(destroyed_group, rules)
        rules.each do |rule|
          protected_environment = rule.protected_environment

          audit_context = {
            name: 'protected_environment_approval_rule_reassigned',
            # current_user can be nil (e.g. RemoveExpiredMembersWorker
            # calls Users::DestroyService.new(nil)); AuditEvents::BuildService
            # raises on a blank author otherwise.
            author: current_user || ::Gitlab::Audit::UnauthenticatedAuthor.new(name: '(System)'),
            scope: protected_environment.project || protected_environment.group,
            target: protected_environment,
            target_details: protected_environment.name,
            message: "Sole approver group #{destroyed_group.full_path} was permanently deleted; " \
              "approval rule reassigned to require any Maintainer's approval",
            additional_details: {
              action: 'reassign_sole_approver',
              removed_group_id: destroyed_group.id,
              protected_environment_id: protected_environment.id,
              new_access_level: rule.access_level
            }
          }

          ::Gitlab::Audit::Auditor.audit(audit_context)
        end
      end
    end
  end
end
