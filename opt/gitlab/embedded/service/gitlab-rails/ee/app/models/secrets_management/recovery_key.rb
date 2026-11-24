# frozen_string_literal: true

module SecretsManagement
  class RecoveryKey < ApplicationRecord
    self.table_name = 'secrets_management_recovery_keys'

    encrypts :key

    validates :key, length: { maximum: 10240 }, presence: true
    validates :active, inclusion: [true, false]
    validate :no_other_active

    scope :active, -> { where(active: true) }

    def no_other_active
      return unless active?

      return unless SecretsManagement::RecoveryKey.active.where.not(id: id).take

      errors.add(
        :base,
        _("A maximum of one active RecoveryKey can exist at a time")
      )
    end
  end
end
