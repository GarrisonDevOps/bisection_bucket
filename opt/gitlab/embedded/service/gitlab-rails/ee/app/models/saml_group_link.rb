# frozen_string_literal: true

class SamlGroupLink < ApplicationRecord
  include StripAttribute
  include MemberRoles::MemberRoleRelation
  include ScimPaginatable

  base_access_level_attr :access_level

  belongs_to :group

  strip_attributes! :saml_group_name, :provider

  before_validation :normalize_provider

  validates :group, :access_level, presence: true
  validates :saml_group_name, presence: true, uniqueness: { scope: [:group_id, :provider] }, length: { maximum: 255 }
  validates :provider, length: { maximum: 255 }, allow_nil: true
  validate :access_level_allowed

  scope :by_id_and_group_id, ->(id, group_id) { where(id: id, group_id: group_id) }
  scope :by_saml_group_name, ->(name) { where(saml_group_name: name) }
  scope :by_group_id, ->(group_id) { where(group_id: group_id) }
  scope :by_scim_group_uid, ->(uid) { where(scim_group_uid: uid) }
  scope :by_assign_duo_seats, ->(value) { where(assign_duo_seats: value) }
  scope :by_provider, ->(provider) { where(provider: provider) }
  scope :with_scim_group_uid, -> { where.not(scim_group_uid: nil) }
  scope :preload_group, -> { preload(group: :route) }

  def self.first_by_scim_group_uid(uid)
    by_scim_group_uid(uid).order(:id).take
  end

  def access_level_allowed
    return unless group
    return if access_level.in?(group.access_level_roles.values)

    errors.add(:access_level, "is invalid")
  end

  def human_access
    Gitlab::Access.human_access(access_level)
  end

  private

  def normalize_provider
    self.provider = nil if provider.blank?
  end
end
