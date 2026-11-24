# frozen_string_literal: true

module EE
  module Preview
    module NotifyPreview
      extend ActiveSupport::Concern

      # We need to define the methods on the prepender directly because:
      # https://github.com/rails/rails/blob/3faf7485623da55215d6d7f3dcb2eed92c59c699/actionmailer/lib/action_mailer/preview.rb#L73
      prepended do
        def approved_merge_request_email
          ::Notify.approved_merge_request_email(user.id, merge_request.id, approver.id).message
        end

        def unapproved_merge_request_email
          ::Notify.unapproved_merge_request_email(user.id, merge_request.id, approver.id).message
        end

        def mirror_was_hard_failed_email
          ::Notify.mirror_was_hard_failed_email(project.id, user.id).message
        end

        def mirror_was_disabled_email
          ::Notify.mirror_was_disabled_email(project.id, user.id, 'deleted_user_name').message
        end

        def project_mirror_user_changed_email
          ::Notify.project_mirror_user_changed_email(user.id, 'deleted_user_name', project.id).message
        end

        def send_admin_notification
          ::Notify.send_admin_notification(user.id, 'Email subject from admin', 'Email body from admin').message
        end

        def send_unsubscribed_notification
          ::Notify.send_unsubscribed_notification(user.id).message
        end

        def import_requirements_csv_email
          ::Notify.import_requirements_csv_email(user.id, project.id, { success: 3, errors: [5, 6, 7], valid_file: true })
        end

        def requirements_csv_email
          ::Notify.requirements_csv_email(
            user, project, 'requirement1,requirement2,requirement3',
            { truncated: false, rows_expected: 3, rows_written: 3 }
          ).message
        end

        def user_associated_with_enterprise_group_email
          cleanup do
            associate_user_with_enterprise_group(user, group)

            ::Notify.user_associated_with_enterprise_group_email(user.id).message
          end
        end

        def new_epic_email
          ::Notify.new_epic_email(user.id, epic.id).message
        end

        def merge_commits_csv_email
          ::Notify.merge_commits_csv_email(
            user,
            project.group,
            'one,two,three',
            'filename.csv'
          ).message
        end

        def user_auto_banned_instance_email
          ::Notify.user_auto_banned_email(user.id, user.id, max_project_downloads: 5, within_seconds: 600, auto_ban_enabled: true, ip_address: '192.0.2.1').message
        end

        def user_auto_banned_namespace_email
          ::Notify.user_auto_banned_email(user.id, user.id, max_project_downloads: 5, within_seconds: 600, auto_ban_enabled: true, group: group).message
        end

        def user_cap_reached
          ::Notify.user_cap_reached(user.id).message
        end

        def confirmation_instructions_email
          ::Notify.confirmation_instructions_email(user.email, token: '123456').message
        end

        def no_more_seats
          ::Notify.no_more_seats(user.id, member.user_id, project, ['Patrick Jane', 'Thomas McAllister']).message
        end

        def dormant_user_blocked_on_reactivation_self_managed
          ::Notify.dormant_user_blocked_on_reactivation(user.id, member.user_id).message
        end

        def dormant_user_blocked_on_reactivation_saas
          ::Notify.dormant_user_blocked_on_reactivation(user.id, member.user_id, group.id).message
        end

        def project_secret_rotation_reminder_email
          ::Notify.project_secret_rotation_reminder_email(user.id, project.id, 'DUMMY_PASSWORD').message
        end

        def group_secret_rotation_reminder_email
          ::Notify.group_secret_rotation_reminder_email(user.id, group.id, 'DUMMY_PASSWORD').message
        end

        def virtual_registry_cleanup_complete
          ::Notify.virtual_registry_cleanup_complete(policy, user).message
        end

        def virtual_registry_cleanup_failure
          ::Notify.virtual_registry_cleanup_failure(policy, user).message
        end
      end

      private

      def approver
        @user ||= ::User.first
      end

      def epic
        @epic ||= project.group.epics.first
      end

      def policy
        @policy ||= ::VirtualRegistries::Cleanup::Policy.new(group:)
      end

      def associate_user_with_enterprise_group(user, group)
        user.user_detail.update!(enterprise_group_id: group.id, enterprise_group_associated_at: Time.current)
      end
    end
  end
end
