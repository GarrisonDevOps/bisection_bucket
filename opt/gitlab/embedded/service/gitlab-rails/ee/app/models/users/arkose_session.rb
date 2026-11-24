# frozen_string_literal: true

module Users
  class ArkoseSession < ::ApplicationRecord
    belongs_to :user

    validates :session_xid, length: { maximum: 64 }, presence: true,
      exclusion: { in: ["Unavailable"], message: "Session ID cannot be nil or 'Unavailable'" }
    validates :user_id, presence: true
    validates :challenge_shown, inclusion: { in: [true, false] }
    validates :challenge_solved, inclusion: { in: [true, false] }
    validates :verified_at, presence: true
    validates :session_is_legit, inclusion: { in: [true, false] }
    validates :telltale_user, length: { maximum: 128 }
    validates :user_agent, length: { maximum: 255 }
    validates :user_language_shown, length: { maximum: 64 }
    validates :device_xid, length: { maximum: 64 }
    validates :ja4_hash, length: { maximum: 64 }
    validates :canvas_fingerprint, numericality: { only_integer: true, allow_nil: true }
    validates :telltale_list, presence: true, unless: -> { telltale_list == [] }
    validates :user_ip, length: { maximum: 64 }
    validates :country, length: { maximum: 64 }
    validates :region, length: { maximum: 64 }
    validates :city, length: { maximum: 64 }
    validates :isp, length: { maximum: 128 }
    validates :connection_type, length: { maximum: 64 }
    validates :is_tor, inclusion: { in: [true, false] }
    validates :is_vpn, inclusion: { in: [true, false] }
    validates :is_proxy, inclusion: { in: [true, false] }
    validates :is_bot, inclusion: { in: [true, false] }
    validates :risk_band, length: { maximum: 64 }
    validates :risk_category, length: { maximum: 64 }
    validates :global_score, numericality: { only_integer: true, allow_nil: true }
    validates :custom_score, numericality: { only_integer: true, allow_nil: true }

    def self.create_for_user_from_verify_response(user, response)
      create(
        user: user,
        session_xid: response.session_id,
        challenge_shown: response.challenge_shown?,
        challenge_solved: response.challenge_solved?,
        session_created_at: response.session_created_at,
        checked_answer_at: response.checked_answer_at,
        verified_at: response.verified_at,
        session_is_legit: response.session_is_legit,
        telltale_user: response.telltale_user,
        user_agent: response.user_agent&.truncate(255),
        user_language_shown: response.user_language_shown,
        device_xid: response.device_id,
        ja4_hash: response.ja4_hash,
        canvas_fingerprint: response.canvas_fingerprint,
        telltale_list: response.telltale_list,
        user_ip: response.user_ip,
        country: response.country,
        region: response.region,
        city: response.city,
        isp: response.isp,
        connection_type: response.connection_type,
        is_tor: response.is_tor || false,
        is_vpn: response.is_vpn || false,
        is_proxy: response.is_proxy || false,
        is_bot: response.is_bot || false,
        risk_band: response.risk_band,
        risk_category: response.risk_category,
        global_score: response.global_score,
        custom_score: response.custom_score
      )
    end
  end
end
