# frozen_string_literal: true

module ComplianceManagement
  module Pipl
    COVERED_COUNTRY_CODES = %w[CN HK MO].freeze
    PIPL_SUBJECT_USER_CACHE_KEY = 'pipl_subject_user'

    def self.user_subject_to_pipl?(user)
      user&.pipl_user.present? && Rails.cache.read([PIPL_SUBJECT_USER_CACHE_KEY, user.id]).present?
    end
  end
end
