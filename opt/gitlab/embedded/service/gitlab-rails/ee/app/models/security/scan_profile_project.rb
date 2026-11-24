# frozen_string_literal: true

module Security
  class ScanProfileProject < ::SecApplicationRecord
    self.table_name = 'security_scan_profiles_projects'

    MAX_PROFILES_PER_PROJECT = 10

    belongs_to :project, optional: false
    belongs_to :scan_profile, class_name: 'Security::ScanProfile', foreign_key: :security_scan_profile_id,
      inverse_of: :scan_profile_projects, optional: false

    validates :project_id, uniqueness: { scope: :security_scan_profile_id }
    validates :traversal_ids, presence: true, on: :create

    # Bulk attachment writes traversal_ids in its own INSERT and never reaches this
    # callback. It exists for the `has_many through:` association, which would
    # otherwise leave the column at its `{}` default.
    before_validation :set_traversal_ids, on: :create

    scope :for_projects_and_profile, ->(projects, scan_profile) {
      where(project: projects, scan_profile: scan_profile)
    }

    scope :by_project_id, ->(project_id) { where(project_id: project_id) }
    scope :unarchived, -> { where(archived: false) }
    scope :for_scan_profiles, ->(scan_profile_ids) { where(security_scan_profile_id: scan_profile_ids) }
    scope :not_in_root_namespace, ->(root_namespace) {
      joins(:scan_profile).where.not(security_scan_profiles: { namespace: root_namespace })
    }

    # FOR SHARE makes a concurrent DELETE of these links wait for our transaction.
    def self.lock_linked_profile_ids(project_id, profile_ids)
      by_project_id(project_id).for_scan_profiles(profile_ids).order(:security_scan_profile_id).lock('FOR SHARE')
        .limit(MAX_PLUCK).pluck(:security_scan_profile_id)
    end

    def self.project_ids_with_profile_type(project_ids, namespace_id, scan_type)
      profile_ids = Security::ScanProfile.not_deleted.by_namespace(namespace_id).by_type(scan_type).scan_profile_ids

      by_project_id(project_ids)
        .for_scan_profiles(profile_ids)
        .distinct
        .limit(project_ids.size)
        .pluck(:project_id)
    end

    def self.project_ids
      limit(MAX_PLUCK).pluck(:project_id)
    end

    def self.attached_project_ids(project_ids)
      return [] if project_ids.blank?

      by_project_id(project_ids)
        .distinct
        .limit(project_ids.size)
        .pluck(:project_id)
    end

    def self.sync_archived_for(project_ids)
      projects = preload_archived_state(::Project.id_in(project_ids).to_a)

      archived, unarchived = projects.partition(&:self_or_ancestors_archived?)

      update_archived_for(archived.map(&:id), archived: true) +
        update_archived_for(unarchived.map(&:id), archived: false)
    end

    def self.preload_archived_state(projects)
      ::ActiveRecord::Associations::Preloader.new(
        records: projects,
        associations: [:project_namespace, { namespace: :namespace_settings_with_ancestors_inherited_settings }]
      ).call

      projects
    end

    def self.update_archived_for(project_ids, archived:)
      return 0 if project_ids.blank?

      by_project_id(project_ids)
        .where.not(archived: archived)
        .update_all(archived: archived, updated_at: Time.current)
    end

    private

    def set_traversal_ids
      return if traversal_ids.present? || project.nil?

      self.traversal_ids = project.namespace.traversal_ids
    end
  end
end
