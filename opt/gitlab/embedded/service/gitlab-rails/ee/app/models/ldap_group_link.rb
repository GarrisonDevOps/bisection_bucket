# frozen_string_literal: true

class LdapGroupLink < ApplicationRecord
  include MemberRoles::MemberRoleRelation

  base_access_level_attr :group_access

  belongs_to :group

  BLANK_ATTRIBUTES = %w[cn filter].freeze

  with_options if: :cn do
    validates :cn, uniqueness: { scope: [:group_id, :provider] }
    validates :cn, presence: true
    validates :filter, absence: true
  end

  with_options if: :filter do
    validates :filter, uniqueness: { scope: [:group_id, :provider] }
    validates :filter, ldap_filter: true, presence: true
    validates :cn, absence: true
  end

  validates :filter, length: { maximum: 8192 }, on: :create
  validates :cn, :provider, length: { maximum: 255 }, on: :create

  validates :group_access, presence: true
  validates :provider, presence: true
  validate :cn_or_filter_present, on: :create

  scope :with_provider, ->(provider) { where(provider: provider) }

  before_validation :nullify_blank_attributes

  def human_access
    Gitlab::Access.human_access(group_access)
  end

  def identifier_label
    cn.present? ? "CN - #{cn}" : "Filter - #{filter}"
  end

  def config
    Gitlab::Auth::Ldap::Config.new(provider)
  rescue Gitlab::Auth::Ldap::Config::InvalidProvider
    nil
  end

  # default to the first LDAP server
  def provider
    read_attribute(:provider) || Gitlab::Auth::Ldap::Config.providers.first
  end

  def provider_label
    config.label
  end

  def active?
    if filter.present?
      ::License.feature_available?(:ldap_group_sync_filter)
    elsif cn.present?
      ::License.feature_available?(:ldap_group_sync)
    end
  end

  private

  def nullify_blank_attributes
    BLANK_ATTRIBUTES.each { |attr| self[attr] = nil if self[attr].blank? }
  end

  def cn_or_filter_present
    return if cn.present? || filter.present?

    errors.add(:base, 'Either LDAP group cn or LDAP user filter is required')
  end
end
