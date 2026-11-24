# frozen_string_literal: true

module EE
  module UsersHelper
    extend ::Gitlab::Utils::Override

    override :display_public_email?
    def display_public_email?(user)
      return false if user.public_email.blank?

      return false if user.enterprise_user? && user.enterprise_group&.hide_email_on_profile?

      true
    end

    override :impersonation_tokens_enabled?
    def impersonation_tokens_enabled?
      super && !::Gitlab::CurrentSettings.personal_access_tokens_disabled?
    end

    override :admin_users_data_attributes
    def admin_users_data_attributes(users)
      return super unless current_user&.can_admin_all_resources?

      super.merge({
        is_at_seats_limit: at_seats_limit?.to_s
      })
    end

    override :instance_user_badges
    def instance_user_badges(user)
      super(user).tap do |badges|
        if can?(current_user, :read_user_access_level, :global)
          badges << { text: s_('AdminUsers|Auditor'), variant: 'neutral' } if user.auditor?
          badges << { text: assigned_admin_role(user).name, variant: 'info', icon: 'admin' } if has_admin_role?(user)
        end

        if show_license_seat_badge?(user) && can?(current_user, :read_admin_users, :global)
          badges << { text: s_('AdminUsers|Is using seat'), variant: 'neutral' }
        end
      end
    end

    def user_enterprise_group_text(user)
      enterprise_group = user.user_detail&.enterprise_group
      return unless enterprise_group

      list_item_classes = '!gl-grid @md/panel:gl-grid-cols-3 gl-gap-x-3'
      group_info = link_to enterprise_group.name, admin_group_path(enterprise_group)
      user_enterprise_group = content_tag(:li, class: list_item_classes) do
        content_tag(:span, _("Enterprise user of: "), class: "gl-text-subtle") +
          content_tag(:div, "", class: "gl-col-span-2") do
            content_tag(:strong, group_info) +
              content_tag(:span, format(' (%{gid})', gid: enterprise_group.id), class: "gl-text-subtle")
          end
      end

      user_enterprise_associated = content_tag(:li, class: list_item_classes) do
        content_tag(:span, _("Enterprise user associated at: "), class: "gl-text-subtle") +
          content_tag(:div, class: "gl-col-span-2") do
            content_tag(:strong, user.user_detail.enterprise_group_associated_at.to_fs(:medium))
          end
      end
      user_enterprise_group + user_enterprise_associated
    end

    def has_admin_role?(user)
      License.feature_available?(:custom_roles) && assigned_admin_role(user)
    end

    def assigned_user_admin_role(user)
      extract_admin_roles? ? user.user_admin_role : user.user_member_role
    end

    def assigned_admin_role(user)
      extract_admin_roles? ? user.admin_role : user.member_role
    end

    private

    def extract_admin_roles?
      ::Feature.enabled?(:extract_admin_roles_from_member_roles, :instance)
    end

    def show_license_seat_badge?(user)
      !::Gitlab::Saas.feature_available?(:gitlab_com_subscriptions) && user.using_license_seat?
    end

    override :preload_project_associations
    def preload_project_associations(projects)
      ActiveRecord::Associations::Preloader.new(records: projects, associations: :invited_groups).call
    end

    def at_seats_limit?
      return false if ::Gitlab::Saas.feature_available?(:gitlab_com_subscriptions) # only available for SM instances
      return false unless ::Gitlab::CurrentSettings.seat_control_block_overages?

      licensed_seats = License.current.seats

      return false unless licensed_seats.present? && licensed_seats.nonzero?

      ::User.billable.limit(licensed_seats).count >= licensed_seats
    end
  end
end
