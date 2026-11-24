# frozen_string_literal: true

class NamespaceLimit < ApplicationRecord
  self.primary_key = :namespace_id

  belongs_to :namespace, inverse_of: :namespace_limit

  validates :namespace, presence: true
  validates :additional_purchased_storage_size, presence: true

  validate :namespace_is_root_namespace

  def eligible_additional_purchased_storage_size
    if Feature.enabled?(:expired_storage_check, namespace) &&
        additional_purchased_storage_ends_on &&
        Date.today > additional_purchased_storage_ends_on
      0
    else
      additional_purchased_storage_size
    end
  end

  private

  def namespace_is_root_namespace
    return unless namespace

    errors.add(:namespace, _('must be a root namespace')) if namespace.has_parent?
  end
end
