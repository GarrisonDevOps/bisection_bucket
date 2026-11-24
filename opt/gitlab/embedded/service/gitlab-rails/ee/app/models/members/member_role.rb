# frozen_string_literal: true

class MemberRole < ApplicationRecord # rubocop:disable Gitlab/NamespacedClass
  include GitlabSubscriptions::SubscriptionHelper

  MAX_COUNT_PER_GROUP_HIERARCHY = 10

  # base_access_level is validated against this array,
  # so a migration may be needed if you change it
  LEVELS = ::Gitlab::Access.options_for_custom_roles.values.freeze

  has_many :members
  has_many :saml_providers
  has_many :saml_group_links
  has_many :group_group_links
  has_many :project_group_links
  has_many :ldap_admin_role_links, class_name: 'Authz::LdapAdminRoleLink'
  has_many :users, -> { distinct }, through: :members
  has_many :user_member_roles, class_name: 'Users::UserMemberRole'
  has_many :protected_branch_merge_access_levels,
    class_name: 'ProtectedBranch::MergeAccessLevel',
    inverse_of: :member_role,
    dependent: :restrict_with_error
  has_many :protected_branch_push_access_levels,
    class_name: 'ProtectedBranch::PushAccessLevel',
    inverse_of: :member_role,
    dependent: :restrict_with_error
  has_many :protected_branch_unprotect_access_levels,
    class_name: 'ProtectedBranch::UnprotectAccessLevel',
    inverse_of: :member_role,
    dependent: :restrict_with_error
  belongs_to :namespace
  belongs_to :organization, class_name: 'Organizations::Organization'

  validate :validate_permissions
  validates :name, presence: true
  validates :name, uniqueness: { scope: :namespace_id }
  validates :base_access_level, presence: true, inclusion: { in: LEVELS }, unless: :admin_related_role?
  validates :permissions, json_schema: { filename: 'member_role_permissions' }
  validates :namespace, presence: true, if: :namespace_required?
  validates :namespace, absence: true, if: :admin_related_role?

  validate :belongs_to_top_level_namespace
  validate :max_count_per_group_hierarchy, on: :create
  validate :validate_namespace_locked, on: :update
  validate :base_access_level_locked, on: :update
  validate :validate_requirements
  validate :sharding_key_is_a_single_column

  before_save :set_occupies_seat
  before_destroy :prevent_delete_if_admin_role_assigned, if: :admin_related_role?
  before_destroy :prevent_delete_if_member_associated

  after_commit on: [:create, :destroy] do
    self.class.expire_member_role_exists_cache!(namespace) if namespace
  end

  scope :elevating, -> do
    return none if elevating_permissions.empty?

    first_permission, *other_permissions = elevating_permissions

    scope = permissions_where(first_permission => true)
    other_permissions.each do |permission|
      scope = scope.or(permissions_where(permission => true))
    end

    scope
  end

  scope :occupies_seat, -> { where(occupies_seat: true) }

  scope :by_namespace, ->(group_ids) { where(namespace_id: group_ids) }
  scope :for_instance, -> { where(namespace_id: nil) }
  scope :in_organization, ->(organization) { where(organization: organization) }
  scope :non_admin, -> { where.not(base_access_level: nil) }
  scope :admin, -> { where(base_access_level: nil) }

  scope :with_members_count, -> do
    left_outer_joins(:members)
      .group(:id)
      .select(MemberRole.default_select_columns)
      .select('COUNT(members.id) AS members_count')
  end

  scope :with_users_count, -> do
    left_outer_joins(:members)
      .group(:id)
      .select(MemberRole.default_select_columns)
      .select('COUNT(DISTINCT members.user_id) AS users_count')
  end

  scope :with_ldap_admin_role_links, -> do
    includes(:ldap_admin_role_links)
  end

  jsonb_accessor :permissions, Gitlab::CustomRoles::Definition.all.keys.index_with(:boolean)

  self.filter_attributes = [] # There are no secrets stored in this model, prevent filtering of attributes

  def self.levels_sentence
    ::Gitlab::Access
      .options_with_owner
      .map { |name, value| "#{value} (#{name})" }
      .to_sentence
  end

  def self.declarative_policy_class
    'Members::MemberRolePolicy'
  end

  class << self
    def elevating_permissions
      MemberRole.all_customizable_permissions.reject { |_k, v| v[:skip_seat_consumption] }.keys
    end

    def all_customizable_permissions
      Gitlab::CustomRoles::Definition.all
    end

    def all_customizable_standard_permissions
      Gitlab::CustomRoles::Definition.standard
    end

    def all_customizable_project_permissions
      MemberRole.all_customizable_standard_permissions.select { |_k, v| v[:project_ability] }.keys
    end

    def all_customizable_group_permissions
      MemberRole.all_customizable_standard_permissions.select { |_k, v| v[:group_ability] }.keys
    end

    def customizable_permissions_exempt_from_consuming_seat
      MemberRole.all_customizable_permissions.select { |_k, v| v[:skip_seat_consumption] }.keys
    end

    # This always returns true for self-managed instances.
    # This is only used on SaaS to optimize preloading of custom roles.
    def should_query_custom_roles?(namespace)
      return true unless GitlabSubscriptions::SubscriptionHelper.gitlab_com_subscription?

      Rails.cache.fetch(member_role_exists_cache_key(namespace)) do
        namespace.member_roles.exists?
      end
    end

    def expire_member_role_exists_cache!(namespace)
      return unless GitlabSubscriptions::SubscriptionHelper.gitlab_com_subscription?

      Rails.cache.delete(member_role_exists_cache_key(namespace))
    end

    private

    def member_role_exists_cache_key(namespace)
      ['namespace', namespace.id, 'member_role_exists']
    end
  end

  def dependent_security_policies
    return Security::Policy.none if security_policies_disabled?

    policies = Security::Policy.for_custom_role(id)
    return policies unless gitlab_com_subscription?

    policies.for_policy_configuration(
      namespace.all_descendant_security_orchestration_policy_configurations(include_invalid: true)
    )
  end

  def admin_related_role?
    enabled_admin_permissions.present? && base_access_level.nil?
  end

  def enabled_permissions
    self.class.all_customizable_permissions.filter do |permission, _|
      attributes[permission.to_s]
    end
  end

  def enabled_admin_permissions
    Gitlab::CustomRoles::Definition.admin.filter do |permission, _|
      attributes[permission.to_s]
    end
  end

  def namespace_required?
    return false unless gitlab_com_subscription?

    !admin_related_role?
  end

  private

  def validate_permissions
    self.permissions = permissions.select { |_, enabled| enabled }

    if permissions.empty?
      errors.add(:base, s_('MemberRole|Cannot create a member role with no enabled permissions'))
      return
    end

    allowed_permissions = available_permissions
    permissions.each_key do |permission|
      next if allowed_permissions.include?(permission.to_sym)

      message = format(s_('MemberRole|Unknown permission: %{permission}'), permission: permission)
      errors.add(:base, message)
    end
  end

  def available_permissions
    if admin_related_role?
      Gitlab::CustomRoles::Definition.admin
    else
      self.class.all_customizable_standard_permissions
    end
  end

  def security_policies_disabled?
    if gitlab_com_subscription?
      return !::Security::PolicyAvailability.available?(namespace, :security_orchestration_policies)
    end

    !License.feature_available?(:security_orchestration_policies)
  end

  def belongs_to_top_level_namespace
    return if !namespace || namespace.root?

    errors.add(:namespace, s_("MemberRole|must be top-level namespace"))
  end

  def max_count_per_group_hierarchy
    return unless namespace
    return if namespace.member_roles.count < MAX_COUNT_PER_GROUP_HIERARCHY

    errors.add(
      :namespace,
      s_(
        "MemberRole|maximum number of Member Roles are already in use by the group hierarchy. " \
        "Please delete an existing Member Role."
      )
    )
  end

  def validate_namespace_locked
    return unless namespace_id_changed?

    errors.add(:namespace, s_("MemberRole|can't be changed"))
  end

  def validate_requirements
    self.class.all_customizable_permissions.each do |permission, params|
      requirements = params[:requirements]

      next unless self[permission] # skipping permissions not set for the object
      next unless requirements.present? # skipping permissions that have no requirements

      requirements.each do |requirement|
        next if self[requirement] # the requirement is met
        next if requirement_included_in_base_access_level?(requirement)

        errors.add(:base,
          format(s_("MemberRole|%{requirement} has to be enabled in order to enable %{permission}"),
            requirement: requirement.to_s.humanize, permission: permission.to_s.humanize)
        )
      end
    end
  end

  def requirement_included_in_base_access_level?(requirement)
    return false unless base_access_level

    permission = self.class.all_customizable_permissions[requirement.to_sym]
    return false unless permission

    group_levels = permission[:enabled_for_group_access_levels]
    project_levels = permission[:enabled_for_project_access_levels]

    enabled_for = if group_levels && project_levels
                    group_levels & project_levels
                  else
                    group_levels || project_levels || []
                  end

    enabled_for.include?(base_access_level)
  end

  def base_access_level_locked
    return unless changed_attributes.include?('base_access_level')

    errors.add(
      :base_access_level,
      s_('MemberRole|cannot be changed. Please create a new Member Role instead.')
    )
  end

  def prevent_delete_if_admin_role_assigned
    if user_member_roles.exists?
      errors.add(:base,
        s_("MemberRole|Admin role is assigned to one or more users. " \
          "Remove role from all users, then delete role."))

      throw :abort # rubocop:disable Cop/BanCatchThrow -- Stops the destroy. Adding an error alone would not.
    elsif ldap_admin_role_links.exists?
      errors.add(:base,
        s_("MemberRole|Admin role is used by one or more LDAP synchronizations. " \
          "Remove LDAP syncs, then delete role."))

      throw :abort # rubocop:disable Cop/BanCatchThrow -- Stops the destroy. Adding an error alone would not.
    end
  end

  def prevent_delete_if_member_associated
    return unless members.present?

    errors.add(
      :base,
      s_(
        "MemberRole|Role is assigned to one or more group members. " \
        "Remove role from all group members, then delete role."
      )
    )

    throw :abort # rubocop:disable Cop/BanCatchThrow
  end

  def set_occupies_seat
    return true if base_access_level.nil?

    self.occupies_seat = base_access_level > Gitlab::Access::GUEST ||
      self.class.elevating_permissions.any? { |attr| self[attr] }
  end

  def sharding_key_is_a_single_column
    return if namespace.present? ^ organization.present?

    errors.add(:base, s_('MemberRole|A sharding key (namespace_id or organization_id) is required'))
  end
end
