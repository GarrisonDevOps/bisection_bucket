# frozen_string_literal: true

class Groups::Security::CredentialsController < Groups::ApplicationController
  layout 'group'

  extend ::Gitlab::Utils::Override
  include CredentialsInventoryActions
  include Groups::SecurityFeaturesHelper
  include ProductAnalyticsTracking

  helper_method :credentials_inventory_path, :user_detail_path, :personal_access_token_revoke_path,
    :resource_access_token_revoke_path, :ssh_key_delete_path

  before_action :validate_group_level_credentials_inventory_available!, only: [:index, :revoke, :destroy]
  before_action :check_gpg_keys_list_enabled!, only: [:index]

  feature_category :user_management

  track_internal_event :index, name: 'visit_authentication_credentials_inventory'

  private

  def tracking_project_source
    nil
  end

  def tracking_namespace_source
    group
  end

  def validate_group_level_credentials_inventory_available!
    render_404 unless group_level_credentials_inventory_available?(group)
  end

  def check_gpg_keys_list_enabled!
    render_404 if show_gpg_keys?
  end

  override :credentials_inventory_path
  def credentials_inventory_path(args)
    group_security_credentials_path(args)
  end

  override :ssh_key_delete_path
  def ssh_key_delete_path(key)
    group_security_credential_path(@group, key)
  end

  override :user_detail_path
  def user_detail_path(user)
    user_path(user)
  end

  override :personal_access_token_revoke_path
  def personal_access_token_revoke_path(token)
    revoke_group_security_credential_path(group, token)
  end

  override :resource_access_token_revoke_path
  def resource_access_token_revoke_path(...)
    group_security_credential_resource_revoke_path(...)
  end

  override :users
  def users
    group.enterprise_users.or(group.service_accounts)
  end

  override :bot_users
  def bot_users
    User.by_bot_namespace_ids(group.self_and_descendants(skope: Namespace).as_ids)
  end

  override :revocable
  def revocable
    group
  end
end
