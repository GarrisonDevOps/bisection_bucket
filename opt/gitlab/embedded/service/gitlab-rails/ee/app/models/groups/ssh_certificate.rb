# frozen_string_literal: true

module Groups
  class SshCertificate < ApplicationRecord
    include SshCertificateValidations

    self.table_name = :group_ssh_certificates

    belongs_to :group, foreign_key: :namespace_id, inverse_of: :ssh_certificates

    scope :for_namespace, ->(namespace_id) { where(namespace_id: namespace_id) }

    validates :group, presence: true

    validates :fingerprint,
      uniqueness: { scope: :namespace_id,
                    message: ->(_, _) {
                      _('must be unique. This CA has already been configured for this namespace.')
                    } }
  end
end
