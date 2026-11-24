# frozen_string_literal: true

class ScimOauthAccessToken < ApplicationRecord
  include TokenAuthenticatable

  ignore_column :group_id, remove_with: '19.8', remove_after: '2026-12-17'

  TOKEN_PREFIX = 'glsoat-'

  belongs_to :organization, class_name: 'Organizations::Organization'

  add_authentication_token_field :token, encrypted: :required, format_with_prefix: :prefix_for_token

  validates :organization_id, presence: true, on: :create

  before_save :ensure_token

  def self.prefix_for_token
    ::Authn::TokenField::PrefixHelper.prepend_instance_prefix(TOKEN_PREFIX)
  end

  def as_entity_json
    ScimOauthAccessTokenEntity.new(self).as_json
  end

  def prefix_for_token
    self.class.prefix_for_token
  end
end
