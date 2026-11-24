# frozen_string_literal: true

module Ci
  class RunnerControllerToken < Ci::ApplicationRecord
    include RedisCacheable
    include TokenAuthenticatable

    TOKEN_PREFIX = "glrct-"

    add_authentication_token_field :token,
      digest: true,
      format_with_prefix: :token_prefix

    INACTIVE_AFTER = 1.hour.freeze

    cached_attr_reader :last_used_at

    belongs_to :runner_controller,
      class_name: 'Ci::RunnerController',
      inverse_of: :tokens

    validates :description, length: { maximum: 1024 }

    before_create :ensure_token

    enum :status, {
      active: 0,
      revoked: 1
    }

    scope :connected, -> { active.where("last_used_at > ?", INACTIVE_AFTER.ago) }

    def self.token_prefix
      ::Authn::TokenField::PrefixHelper.prepend_instance_prefix(TOKEN_PREFIX)
    end

    def revoke!
      update(status: :revoked)
    end

    private

    def token_prefix
      self.class.token_prefix
    end
  end
end
