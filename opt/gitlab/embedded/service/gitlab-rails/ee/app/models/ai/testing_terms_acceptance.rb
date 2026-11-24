# frozen_string_literal: true

module Ai
  class TestingTermsAcceptance < ApplicationRecord
    self.table_name = "ai_testing_terms_acceptances"
    self.primary_key = :user_id

    validates :user_id, presence: true
    validates :user_email, presence: true, length: { maximum: 255 }

    def self.has_accepted?
      exists?
    end
  end
end
