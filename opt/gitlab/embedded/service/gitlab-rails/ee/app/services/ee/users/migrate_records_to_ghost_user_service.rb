# frozen_string_literal: true

module EE
  module Users
    module MigrateRecordsToGhostUserService
      extend ::Gitlab::Utils::Override

      private

      override :migrate_records
      def migrate_records
        # these should always be ghosted
        migrate_resource_iteration_events
        migrate_resource_link_events

        return super if hard_delete

        migrate_epics
        migrate_vulnerabilities_feedback
        migrate_vulnerabilities
        migrate_vulnerabilities_external_issue_links
        super
      end

      # Approval-rule reassignment already ran inside User's before_destroy
      # callback, as part of the same transaction as super's destroy call.
      # This method only reads the memoized result to log it.
      override :post_migrate_records
      def post_migrate_records
        destroyed = super.try(:destroyed?)

        # Skip logging if destroy didn't commit - a later before_destroy
        # callback may have aborted it, rolling back the reassignment even
        # though these in-memory rule objects still look reassigned.
        return unless destroyed

        reassigned_rules = user.reassigned_protected_environment_approval_rules
        log_protected_environment_reassignment_audit_events(reassigned_rules) if reassigned_rules.present?

        log_audit_event(user)
      end

      # `update_all` skips callbacks, so reindex the moved snippets: their author, and with it `hidden`, changed.
      override :migrate_snippets
      def migrate_snippets
        return super unless ::Gitlab::CurrentSettings.elasticsearch_indexing?

        snippet_ids = user.snippets.only_project_snippets.pluck_primary_key
        super

        snippet_ids.each_slice(::Search::Elastic::Reference::PRELOAD_BATCH_SIZE) do |ids|
          ::Elastic::ProcessBookkeepingService.track!(*::Snippet.id_in(ids).select(:id, :type))
        end
      end

      def migrate_epics
        batched_migrate(::Epic, :author_id)
        batched_migrate(::Epic, :last_edited_by_id)
      end

      def migrate_vulnerabilities_feedback
        batched_migrate(Vulnerabilities::Feedback, :author_id)
        batched_migrate(Vulnerabilities::Feedback, :comment_author_id)
      end

      def migrate_vulnerabilities
        batched_migrate(::Vulnerability, :author_id)
      end

      def migrate_vulnerabilities_external_issue_links
        batched_migrate(Vulnerabilities::ExternalIssueLink, :author_id)
      end

      def migrate_resource_iteration_events
        batched_migrate(ResourceIterationEvent, :user_id)
      end

      def migrate_resource_link_events
        batched_migrate(::WorkItems::ResourceLinkEvent, :user_id)
      end

      def log_audit_event(user)
        audit_context = {
          name: 'user_records_migrated_to_ghost',
          author: initiator_user,
          scope: user,
          target: user,
          target_details: user.full_path,
          message: 'User records migrated to ghost user',
          additional_details: {
            action: 'migrate_to_ghost',
            author_name: initiator_user.name,
            target_id: user.id,
            target_type: 'User'
          }
        }

        ::Gitlab::Audit::Auditor.audit(audit_context)
      end

      # One audit event per reassigned rule.
      def log_protected_environment_reassignment_audit_events(rules)
        rules.each do |rule|
          protected_environment = rule.protected_environment

          audit_context = {
            name: 'protected_environment_approval_rule_reassigned',
            # initiator_user can be nil (e.g. RemoveExpiredMembersWorker
            # calls Users::DestroyService.new(nil)); AuditEvents::BuildService
            # raises on a blank author otherwise.
            author: initiator_user || ::Gitlab::Audit::UnauthenticatedAuthor.new(name: '(System)'),
            scope: protected_environment.project || protected_environment.group,
            target: protected_environment,
            target_details: protected_environment.name,
            message: "Sole approver #{user.username} was permanently deleted; " \
              "approval rule reassigned to require any Maintainer's approval",
            additional_details: {
              action: 'reassign_sole_approver',
              removed_user_id: user.id,
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
