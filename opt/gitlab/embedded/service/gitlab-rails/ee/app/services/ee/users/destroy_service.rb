# frozen_string_literal: true

module EE
  module Users
    module DestroyService
      extend ::Gitlab::Utils::Override

      override :execute
      def execute(user, options = {})
        result = super(user, options) do |delete_user|
          mirror_cleanup(delete_user)
          oncall_rotations_cleanup(delete_user)
          escalation_rules_cleanup(delete_user)
        end

        log_audit_event(user, options)

        result
      end

      def mirror_cleanup(user)
        user_mirrors = ::Project.where(mirror_user: user) # rubocop: disable CodeReuse/ActiveRecord

        user_mirrors.find_each do |mirror|
          mirror.update(mirror: false, mirror_user: nil)
          ::Gitlab::ErrorTracking.track_exception(
            RuntimeError.new('Disabled mirroring'),
            user_id: user.id,
            project_id: mirror.id
          )

          ::NotificationService.new.mirror_was_disabled(mirror, user.name)
        end
      end

      def oncall_rotations_cleanup(user)
        ::IncidentManagement::OncallRotations::RemoveParticipantsService.new(
          user.oncall_rotations,
          user,
          false
        ).execute
      end

      def escalation_rules_cleanup(user)
        rules = ::IncidentManagement::EscalationRulesFinder.new(user: user, include_removed: true).execute

        ::IncidentManagement::EscalationRules::DestroyService.new(escalation_rules: rules, user: user).execute
      end

      private

      def first_mirror_owner(user, mirror)
        mirror_owners = mirror.team.owners
        mirror_owners -= [user]

        mirror_owners.first
      end

      def log_audit_event(user, options)
        audit_context = {
          name: 'user_destroyed',
          author: current_user || ::Gitlab::Audit::UnauthenticatedAuthor.new(name: '(System)'),
          target: user,
          target_details: user.full_path,
          message: "User #{user.username} scheduled for deletion"
        }

        audit_context[:message] += ". Reason: #{options[:reason_for_deletion]}" if options[:reason_for_deletion]

        audit_context[:scope] =
          if user.project_bot? && options[:project_bot_resource]
            options[:project_bot_resource]
          elsif user.provisioned_by_group
            user.provisioned_by_group
          else
            user
          end

        ::Gitlab::Audit::Auditor.audit(audit_context)
      end
    end
  end
end
