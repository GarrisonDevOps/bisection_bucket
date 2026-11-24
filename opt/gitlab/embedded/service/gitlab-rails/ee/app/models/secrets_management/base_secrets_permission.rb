# frozen_string_literal: true

require 'time'

module SecretsManagement
  class BaseSecretsPermission
    include ActiveModel::Model
    include ActiveModel::Attributes
    include ActiveModel::Validations

    # group or project the secrets being permitted belong to
    attribute :resource

    # Principal that has the permission (user, role, member role)
    attribute :principal_id, :integer
    attribute :principal_type, :string

    # Additional metadata
    attribute :actions
    attribute :granted_by, :integer
    attribute :expired_at, :string

    validates :resource, presence: true
    validates :principal_id, :principal_type, presence: true
    validates :actions, presence: true
    validate :validate_principal_types, :validate_actions, :validate_role_id
    with_options if: :resource do
      validate :valid_principal
    end
    validate :validate_expired_at
    validate :ensure_active_secrets_manager

    PRINCIPAL_TYPES = {
      user: 'User',
      role: 'Role',
      member_role: 'MemberRole'
    }.freeze

    ACTIONS = {
      # `read` is a deprecated alias of `read_metadata`. The frontend still sends
      # it and readback still emits it; the rename is tracked in #623488.
      read: 'read',
      read_metadata: 'read_metadata',
      read_value: 'read_value',
      # `create` grants create without update, so new secrets can be added but
      # existing values cannot be changed. `update` changes existing secrets only.
      create: 'create',
      update: 'update',
      # Deprecated in 19.6: `write` is create + update. Removed in 20.0, see
      # https://gitlab.com/gitlab-org/gitlab/-/work_items/632994.
      write: 'write',
      delete: 'delete'
    }.freeze

    # Actions that grant read on the metadata path (the secret's existence and
    # metadata, not its value). `read_value` grants read on the value path.
    METADATA_READ_ACTIONS = %w[read read_metadata].freeze

    # Internal capabilities used in OpenBao
    CAPABILITIES = {
      read: 'read',
      create: 'create',
      update: 'update',
      delete: 'delete',
      list: 'list',
      scan: 'scan'
    }.freeze

    VALID_PRINCIPAL_TYPES = PRINCIPAL_TYPES.values.freeze
    VALID_ACTIONS = ACTIONS.values.freeze
    VALID_CAPABILITIES = CAPABILITIES.values.freeze
    VALID_ROLES = Gitlab::Access.sym_options.except(:guest, :planner).freeze
    MINIMUM_ACCESS_LEVEL = Gitlab::Access::REPORTER

    delegate :secrets_manager, to: :resource, allow_nil: true

    # `write` is `create` + `update`. A later read of the policy reports `write`
    # for any of these, so the mutation response must say the same. Goes away
    # with `write` in 20.0: https://gitlab.com/gitlab-org/gitlab/-/work_items/632994
    def actions=(value)
      super(normalize_write(value))
    end

    def normalized_expired_at
      return if expired_at.blank?

      expired_at_to_time.to_s
    end

    def resource_id
      resource.id
    end

    # Capabilities for the management policy used by the UI/user mount. Covers
    # metadata read, create, write, and delete. It never grants read on the value
    # path, so the user mount cannot read secret values. `read_value` is handled
    # separately by #api_capabilities. `list` comes only with metadata read,
    # because listing the detailed-metadata path returns every secret's metadata.
    def management_capabilities
      data = Set.new
      metadata = Set.new
      detailed_metadata = Set.new

      Array(actions).each do |action|
        case action
        when 'read', 'read_metadata'
          metadata.merge(%w[read list])
          detailed_metadata << 'list'
        when 'create'
          # No metadata capability: creation writes metadata on the app client, so
          # the value write is the only step this grant has to authorize.
          data << 'create'
        when 'update'
          data << 'update'
          metadata << 'update'
        when 'write'
          data.merge(%w[create update])
          metadata.merge(%w[create update])
        when 'delete'
          data << 'delete'
          metadata << 'delete'
        end
      end

      { data: data.to_a, metadata: metadata.to_a, detailed_metadata: detailed_metadata.to_a }
    end

    # Capabilities for the dedicated read-only policy used by the API mount.
    # Present only when `read_value` is granted: read on the value path, plus
    # list on metadata so the client can discover secret names. This is the only
    # policy that exposes secret values.
    def api_capabilities
      return { data: [], metadata: [], detailed_metadata: [] } unless Array(actions).include?(ACTIONS[:read_value])

      { data: ['read'], metadata: ['list'], detailed_metadata: [] }
    end

    # Rebuild actions from the capabilities found in both policies. Metadata read
    # is emitted as the deprecated `read` alias for now; the rename needs frontend
    # and backend in one change and is tracked in #623488.
    #
    # Write actions are keyed off the data path only: create + update gives
    # `write` until the 20.0 removal, create alone gives `create`, and update
    # alone gives `update`.
    def set_actions_from_capabilities(management_metadata:, management_data:, api_data:)
      self.actions = []
      actions << ACTIONS[:read] if management_metadata.include?(CAPABILITIES[:read])

      if management_data.include?(CAPABILITIES[:create])
        actions << if management_data.include?(CAPABILITIES[:update])
                     ACTIONS[:write]
                   else
                     ACTIONS[:create]
                   end
      elsif management_data.include?(CAPABILITIES[:update])
        actions << ACTIONS[:update]
      end

      actions << ACTIONS[:delete] if management_data.include?(CAPABILITIES[:delete])
      actions << ACTIONS[:read_value] if api_data.include?(CAPABILITIES[:read])
    end

    private

    def normalize_write(value)
      given = Array(value)
      has_write = given.include?(ACTIONS[:write])
      has_create_and_update = given.include?(ACTIONS[:create]) && given.include?(ACTIONS[:update])
      return value unless has_write || has_create_and_update

      (given - [ACTIONS[:create], ACTIONS[:update]]) | [ACTIONS[:write]]
    end

    def validate_principal_types
      return if VALID_PRINCIPAL_TYPES.include?(principal_type)

      errors.add(:principal_type, "must be one of: #{VALID_PRINCIPAL_TYPES.join(', ')}")
    end

    def validate_actions
      unless Array(actions).intersect?(METADATA_READ_ACTIONS) || Array(actions).include?(ACTIONS[:read_value])
        errors.add(:actions, 'must include read, read_metadata, or read_value')
      end

      actions&.each do |action|
        next if VALID_ACTIONS.include?(action)

        errors.add(:actions, "contains invalid action: #{action}")
      end
    end

    def validate_role_id
      return unless principal_type == 'Role' && VALID_ROLES.values.exclude?(principal_id)

      valid_role_names = VALID_ROLES.map { |name, value| "#{name} (#{value})" }.join(', ')
      errors.add(:principal_id, "must be one of: #{valid_role_names}")
    end

    def expired_at_to_time
      Time.zone.parse(expired_at)&.utc&.iso8601
    rescue ArgumentError
      nil
    end

    def expired?
      time = expired_at_to_time
      time.present? && Time.current >= time
    end

    def validate_expired_at
      return if expired_at.blank?

      unless expired_at_to_time
        errors.add(:expired_at, 'invalid time format, must be RFC3339 (e.g., 2025-09-01T00:00:00Z)')

        return
      end

      return unless expired?

      errors.add(:expired_at, 'must be in the future')
    end

    def valid_principal
      return if principal_type == 'Role'

      case principal_type
      when 'User'
        valid_user
      when 'MemberRole'
        valid_member_role
      end
    end

    def valid_user
      user = User.find_by_id(principal_id)
      return errors.add(:principal_id, "user does not exist") if user.nil?

      access_level = resource.max_member_access_for_user(user)

      # Check if user has any actual membership
      if access_level == Gitlab::Access::NO_ACCESS
        return errors.add(:principal_id,
          "user is not a member of the #{resource_type.downcase}")
      end

      errors.add(:principal_id, "user must not be Owner") if access_level == Gitlab::Access::OWNER

      return unless access_level < MINIMUM_ACCESS_LEVEL

      errors.add(:principal_id, "user must have at least Reporter role")
    end

    def valid_member_role
      member_role = MemberRole.find_by_id(principal_id)
      return errors.add(:principal_id, "Member Role does not exist") if member_role.nil?
      return if member_role_has_access_to_resource?(member_role)

      errors.add(:principal_id, "Member Role does not have access to this #{resource_type.downcase}")
    end

    def ensure_active_secrets_manager
      return if secrets_manager&.active_after_refresh?

      errors.add(:base, "#{resource_type} secrets manager is not active.")
    end

    def resource_type
      raise NotImplementedError
    end

    def member_role_has_access_to_resource?(member_role)
      raise NotImplementedError
    end
  end
end
