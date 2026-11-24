# frozen_string_literal: true

class IpRestriction < ApplicationRecord
  INVALID_SUBNET_ERRORS = [IPAddr::AddressFamilyError,
    IPAddr::InvalidAddressError].freeze

  belongs_to :group

  validates :group_id, presence: true
  validates :range, presence: true
  validate :valid_subnet
  validate :allow_root_group_only

  def allows_address?(address)
    begin
      ranges = [IPAddr.new(range)]
    rescue *INVALID_SUBNET_ERRORS
      return false
    end
    ranges += ranges.select(&:ipv4?).map(&:ipv4_mapped)

    ranges.any? { |r| r.include?(address) }
  end

  private

  def valid_subnet
    IPAddr.new(range)
  rescue *INVALID_SUBNET_ERRORS
    errors.add(:range, _('is an invalid IP address range'))
  end

  def allow_root_group_only
    if group&.parent_id
      errors.add(:base, _('IP subnet restriction only allowed for top-level groups'))
    end
  end
end
