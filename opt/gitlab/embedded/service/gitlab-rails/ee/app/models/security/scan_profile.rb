# frozen_string_literal: true

module Security
  class ScanProfile < ::SecApplicationRecord
    include StripAttribute

    DEFAULT_CI_TEMPLATE_NAME = 'default'
    CI_TEMPLATE_NAMES = {
      dependency_scanning: 'v2'
    }.freeze

    MAX_PROFILES_PER_NAMESPACE = 20

    self.table_name = 'security_scan_profiles'

    ignore_column :configuration, remove_with: '19.4', remove_after: '2026-09-01'

    strip_attributes! :name, :description

    attr_writer :preset_key # Virtual, non-persisted identifier for default profiles; falls back to scan_type.

    belongs_to :namespace, optional: false

    enum :scan_type, Enums::Security.security_profile_types

    has_many :scan_profile_projects, class_name: 'Security::ScanProfileProject',
      foreign_key: :security_scan_profile_id, inverse_of: :scan_profile
    has_many :projects, through: :scan_profile_projects
    has_many :security_scan_profile_project_statuses, class_name: 'Security::ScanProfileProjectStatus',
      foreign_key: :security_scan_profile_id, inverse_of: :scan_profile
    has_many :scan_profile_triggers, class_name: 'Security::ScanProfileTrigger',
      foreign_key: :security_scan_profile_id, inverse_of: :scan_profile
    has_many :configurations, class_name: 'Security::ScanProfiles::Configuration',
      foreign_key: :security_scan_profile_id, inverse_of: :scan_profile

    accepts_nested_attributes_for :scan_profile_triggers

    validates :scan_type, presence: true
    validates :gitlab_recommended, inclusion: { in: [true, false] }
    validates :name, length: { maximum: 255 }, presence: true,
      uniqueness: {
        scope: [:namespace_id, :scan_type],
        case_sensitive: false,
        conditions: -> { where(deleted_at: nil) }
      }
    validates :description, length: { maximum: 2047 }, allow_blank: true
    validate :root_namespace_validation
    validate :namespace_profiles_limit, on: :create
    validate :name_available, if: :name_changed?

    before_validation :set_triggers_namespace

    scope :not_deleted, -> { where(deleted_at: nil) }
    scope :deleted, -> { where.not(deleted_at: nil) }
    scope :by_namespace, ->(namespace) { where(namespace: namespace) }
    scope :by_type, ->(type) { where(scan_type: type) }
    scope :by_name, ->(name) { where(name: name) }
    scope :by_name_case_insensitive, ->(name) { where(arel_table[:name].lower.eq(name.to_s.downcase)) }
    scope :by_gitlab_recommended, ->(gitlab_recommended = true) { where(gitlab_recommended: gitlab_recommended) }
    scope :with_trigger_type, ->(trigger_type) {
      joins(:scan_profile_triggers).where(security_scan_profile_triggers: { trigger_type: trigger_type })
    }
    scope :scanner, -> { where(scan_type: Enums::Security.scan_profile_types.keys) }
    scope :remediation, -> { where(scan_type: Enums::Security.remediation_scan_profile_types.keys) }
    scope :not_flow_backed, -> { where.not(scan_type: Enums::Security::FLOW_BACKED_SCAN_TYPES) }
    scope :with_trigger_configurations, -> { includes(scan_profile_triggers: :configuration) }

    def self.scan_type_names_for_project(project)
      return [] unless project

      project.security_scan_profiles
        .not_deleted
        .scanner
        .distinct
        .limit(Enums::Security.scan_profile_types.size)
        .pluck(:scan_type)
    end

    def self.scan_profile_ids(limit = MAX_PLUCK)
      limit(limit).ids
    end

    def self.other_with_same_type(profile)
      not_deleted.by_namespace(profile.namespace_id).by_type(profile.scan_type)
        .where.not(id: profile.id)
    end

    def self.project_counts_by_id(scan_profile_ids)
      Security::ScanProfileProject
        .for_scan_profiles(scan_profile_ids)
        .unarchived
        .group(:security_scan_profile_id)
        .count
    end

    def self.really_destroy_all!(ids)
      return 0 if ids.blank?

      where(id: ids).delete_all
    end

    def ci_template_name
      CI_TEMPLATE_NAMES.fetch(scan_type&.to_sym, DEFAULT_CI_TEMPLATE_NAME)
    end

    def preset_key
      @preset_key || scan_type
    end

    def remediation?
      Enums::Security.remediation_scan_profile_types.key?(scan_type&.to_sym)
    end

    def scanner?
      Enums::Security.scan_profile_types.key?(scan_type&.to_sym)
    end

    def effective_configuration_for(trigger_type, project: nil)
      trigger = scan_profile_triggers.find { |t| t.trigger_type == trigger_type.to_s }

      Security::ScanProfiles::Configuration.effective_for(self, trigger, project: project)
    end

    def delete_unreferenced_configurations!
      configurations.where.missing(:scan_profile_triggers).delete_all
    end

    def namespace_profiles_limit
      return unless namespace
      return if self.class.not_deleted.by_namespace(namespace).count < MAX_PROFILES_PER_NAMESPACE

      errors.add(:namespace, format(s_('SecurityScanProfile|cannot have more than %{count} scan profiles.'),
        count: MAX_PROFILES_PER_NAMESPACE))
    end

    # Soft-delete: hide the profile immediately. A background worker performs the
    # project-association cleanup and the hard delete (see DeleteScanProfileService).
    def destroy
      return if gitlab_recommended?

      # update_columns skips validations so soft-delete is never blocked by
      # unrelated validation state (e.g. a namespace that is no longer a root).
      update_columns(deleted_at: Time.current)
    end

    def really_destroy!
      self.class.where(id: id).delete_all
    end

    def deleted?
      deleted_at.present?
    end

    private

    def root_namespace_validation
      errors.add(:namespace, 'must be a root namespace.') unless namespace&.root?
    end

    def name_available
      return if gitlab_recommended? || !name_reserved?

      errors.add(:name, s_('SecurityScanProfile|is reserved for GitLab-recommended scan profiles.'))
    end

    def name_reserved?
      ::Security::DefaultScanProfiles.reserved_name?(name)
    end

    def set_triggers_namespace
      scan_profile_triggers.each do |trigger|
        trigger.namespace ||= namespace
      end
    end
  end
end
