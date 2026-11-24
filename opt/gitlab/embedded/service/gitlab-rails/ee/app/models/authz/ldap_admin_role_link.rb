# frozen_string_literal: true

module Authz
  class LdapAdminRoleLink < ApplicationRecord
    include NullifyIfBlank

    MAX_ERROR_LENGTH = 255

    self.table_name = 'ldap_admin_role_links'

    belongs_to :member_role
    belongs_to :admin_role, class_name: 'Authz::AdminRole', optional: true
    belongs_to :organization, class_name: 'Organizations::Organization', optional: false

    enum :sync_status, {
      never_synced: 0,
      queued: 1,
      running: 2,
      failed: 3,
      successful: 4
    }, default: :never_synced

    validates :sync_status, presence: true
    validates :sync_error, length: { maximum: MAX_ERROR_LENGTH }

    validates :member_role, :provider, presence: true
    validates :provider, :cn, :filter, length: { maximum: 255 }

    validate :provider_is_valid, if: -> { provider.present? }

    with_options if: :cn do
      validates :cn, uniqueness: { scope: [:provider] }
      validates :cn, presence: true
      validates :filter, absence: { message: _('One and only one of [cn, filter] arguments is required') }
    end

    with_options if: :filter do
      validates :filter, uniqueness: { scope: [:provider] }
      validates :filter, ldap_filter: true, presence: true
    end

    nullify_if_blank :cn, :filter

    scope :with_provider, ->(provider) { where(provider: provider) }

    scope :preload_admin_role, -> { preload(:member_role) }
    scope :preload_authz_admin_role, -> { preload(:admin_role) }

    def self.mark_syncs_as_queued
      update_all(
        sync_status: :queued,
        sync_started_at: nil,
        sync_ended_at: nil,
        sync_error: nil
      )
    end

    def self.mark_syncs_as_running
      update_all(
        sync_status: :running,
        sync_started_at: DateTime.current
      )
    end

    def self.mark_syncs_as_successful
      update_all(
        sync_status: :successful,
        sync_ended_at: DateTime.current,
        last_successful_sync_at: DateTime.current,
        sync_error: nil
      )
    end

    def self.mark_syncs_as_failed(error_message, sync_started_at: nil)
      attrs = {
        sync_status: :failed,
        sync_ended_at: DateTime.current,
        sync_error: error_message.truncate(MAX_ERROR_LENGTH)
      }

      attrs[:sync_started_at] = sync_started_at if sync_started_at

      update_all(attrs)
    end

    private

    def provider_is_valid
      return if Gitlab::Auth::Ldap::Config.valid_provider?(provider)

      errors.add(:provider, 'is invalid')
    end
  end
end
