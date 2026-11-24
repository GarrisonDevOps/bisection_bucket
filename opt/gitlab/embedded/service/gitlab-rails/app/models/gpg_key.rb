# frozen_string_literal: true

class GpgKey < ApplicationRecord
  KEY_PREFIX = '-----BEGIN PGP PUBLIC KEY BLOCK-----'
  KEY_SUFFIX = '-----END PGP PUBLIC KEY BLOCK-----'

  include ShaAttribute
  include Cells::Claimable

  cells_claims_attribute :fingerprint, type: CLAIMS_CLAIM_TYPE::CLAIM_TYPE_GPG_KEY_FINGERPRINT

  cells_claims_metadata subject_type: CLAIMS_SUBJECT_TYPE::USER, subject_key: :user_id

  sha_attribute :primary_keyid
  sha_attribute :fingerprint

  belongs_to :user
  has_many :gpg_signatures, class_name: 'CommitSignatures::GpgSignature'
  has_many :subkeys, class_name: 'GpgKeySubkey'

  scope :with_subkeys, -> { includes(:subkeys) }
  scope :externally_valid, -> { where(externally_verified: true) }

  validates :user, presence: true

  validates :key,
    presence: true,
    uniqueness: true,
    format: {
      with: /\A#{KEY_PREFIX}((?!#{KEY_PREFIX})(?!#{KEY_SUFFIX}).)+#{KEY_SUFFIX}\Z/mo,
      message: "is invalid. A valid public GPG key begins with '#{KEY_PREFIX}' and ends with '#{KEY_SUFFIX}'"
    }

  validate :supported_key_packets, if: :key_changed?, unless: -> { errors.has_key?(:key) }

  validates :fingerprint,
    presence: true,
    uniqueness: true,
    # only validate when the `key` is valid, as we don't want the user to show
    # the error about the fingerprint
    unless: -> { errors.has_key?(:key) || errors.has_key?(:base) }

  validates :primary_keyid,
    presence: true,
    uniqueness: true,
    # only validate when the `key` is valid, as we don't want the user to show
    # the error about the fingerprint
    unless: -> { errors.has_key?(:key) || errors.has_key?(:base) }

  before_validation :extract_fingerprint, :extract_primary_keyid, if: :key_changed?
  after_create :generate_subkeys
  after_commit :update_invalid_gpg_signatures, on: :create

  def primary_keyid
    super&.upcase
  end
  alias_method :keyid, :primary_keyid

  def fingerprint
    super&.upcase
  end

  def key=(value)
    super(value&.strip)
  end

  def user_infos
    @user_infos ||= Gitlab::Gpg.user_infos_from_key(key)
  end

  def verified_user_infos
    user_infos.select do |user_info|
      user.verified_email?(user_info[:email])
    end
  end

  def emails_with_verified_status
    user_infos.to_h do |user_info|
      [
        user_info[:email],
        user.verified_email?(user_info[:email])
      ]
    end
  end

  def verified?
    emails_with_verified_status.values.any?
  end

  def verified_and_belongs_to_email?(email)
    emails_with_verified_status.fetch(email.downcase, false)
  end

  def update_invalid_gpg_signatures
    InvalidGpgSignatureUpdateWorker.perform_async(self.id)
  end

  def revoke
    CommitSignatures::GpgSignature
      .with_key_and_subkeys(self)
      .where.not(verification_status: CommitSignatures::GpgSignature.verification_statuses[:unknown_key])
      .update_all(
        gpg_key_id: nil,
        gpg_key_subkey_id: nil,
        verification_status: CommitSignatures::GpgSignature.verification_statuses[:unknown_key],
        updated_at: Time.zone.now
      )

    destroy
  end

  private

  def supported_key_packets
    reason = Gitlab::Gpg::PacketGuard.key_rejection_reason(key)
    return unless reason

    errors.add(:base, key_packet_error_message(reason))
  end

  def key_packet_error_message(reason)
    case reason
    when 'oversized_input'
      format(s_('GpgKey|The GPG key is too large. The maximum size is %{max_size}.'),
        max_size: ActiveSupport::NumberHelper.number_to_human_size(Gitlab::Gpg::PacketGuard::MAX_KEY_SIZE)
      )
    when 'oversized_user_id'
      format(
        ns_('GpgKey|The GPG key contains a user ID longer than %{max_user_id_size} byte.',
          'GpgKey|The GPG key contains a user ID longer than %{max_user_id_size} bytes.',
          Gitlab::Gpg::PacketGuard::MAX_USER_ID_SIZE),
        max_user_id_size: Gitlab::Gpg::PacketGuard::MAX_USER_ID_SIZE
      )
    when 'invalid_armor'
      s_('GpgKey|The GPG key is not a valid ASCII-armored public key.')
    when 'invalid_packet'
      s_('GpgKey|The GPG key contains malformed data.')
    when 'disallowed_packet'
      s_('GpgKey|The GPG key contains unsupported data, such as a private key or compressed packets.')
    else
      Gitlab::ErrorTracking.track_and_raise_for_dev_exception(
        ArgumentError.new("Unknown GPG key packet rejection reason: #{reason}")
      )

      s_('GpgKey|The GPG key is invalid or contains unsupported data.')
    end
  end

  def extract_fingerprint
    # we can assume that the result only contains one item as the validation
    # only allows one key
    self.fingerprint = Gitlab::Gpg.fingerprints_from_key(key).first
  end

  def extract_primary_keyid
    # we can assume that the result only contains one item as the validation
    # only allows one key
    self.primary_keyid = Gitlab::Gpg.primary_keyids_from_key(key).first
  end

  def generate_subkeys
    gpg_subkeys = Gitlab::Gpg.subkeys_from_key(key)

    gpg_subkeys[primary_keyid]&.each do |subkey_data|
      subkeys.create!(keyid: subkey_data[:keyid], fingerprint: subkey_data[:fingerprint])
    end
  end
end

GpgKey.prepend_mod_with('GpgKey')
