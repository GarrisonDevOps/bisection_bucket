# frozen_string_literal: true

class GroupScimAuthAccessToken < ApplicationRecord # rubocop:disable Gitlab/NamespacedClass,Gitlab/BoundedContexts -- Split from existing file
  include TokenAuthenticatable

  ignore_column :temp_source_id, remove_with: '18.8', remove_after: '2025-12-22'

  TOKEN_PREFIX = 'glsoat-'

  belongs_to :group

  add_authentication_token_field :token, encrypted: :required, format_with_prefix: :prefix_for_token

  before_save :ensure_token

  def self.token_matches_for_group?(token, group)
    # Necessary to call `Authn::TokenField::Encrypted.find_token_authenticatable`
    token = find_by_token(token)

    token && group && token.group_id == group.id
  end

  def self.prefix_for_token
    ::Authn::TokenField::PrefixHelper.prepend_instance_prefix(TOKEN_PREFIX)
  end

  def as_entity_json
    Authn::GroupScimAuthAccessTokenEntity.new(self).as_json
  end

  def prefix_for_token
    self.class.prefix_for_token
  end
end
