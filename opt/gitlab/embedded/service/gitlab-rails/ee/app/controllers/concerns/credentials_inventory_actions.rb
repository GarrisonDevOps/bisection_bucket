# frozen_string_literal: true

module CredentialsInventoryActions
  extend ActiveSupport::Concern
  include CredentialsInventoryHelper

  def index
    credentials = filter_credentials.page(credentials_params[:page])
    credentials = credentials.preload_granular_scopes if show_personal_access_tokens?

    @credentials = credentials.preload_users.without_count.load

    respond_to do |format|
      format.html do
        render 'shared/credentials_inventory/index'
      end
    end
  end

  def destroy
    key = KeysFinder.new({ users: users, key_type: 'ssh' }).find_by_id(credentials_params[:id])

    return render_404 if key.nil?

    alert = if Keys::DestroyService.new(current_user).execute(key)
              notify_deleted_or_revoked_credential(key)
              _('User key was successfully removed.')
            else
              _('Failed to remove user key.')
            end

    redirect_to credentials_inventory_path(filter: 'ssh_keys'), status: :found, notice: alert
  end

  def revoke
    personal_access_token = personal_access_token_finder.find_by_id(
      credentials_params[:id] || credentials_params[:credential_id]
    )
    return render_404 unless personal_access_token
    return render_404 if credentials_params[:resource_id] && !resource_type

    result = revoke_service(
      personal_access_token,
      resource_type: resource_type,
      resource_id: credentials_params[:resource_id]
    ).execute

    if result.success?
      flash[:notice] = result.message
      notify_deleted_or_revoked_credential(personal_access_token)
    else
      flash[:alert] = result.message
    end

    redirect_to credentials_inventory_path(page: credentials_params[:page])
  end

  private

  def credentials_params
    params.permit(:page, :id, :credential_id, :resource_id, :resource_type)
  end

  def filter_credentials
    if show_personal_access_tokens?
      PersonalAccessTokensFinder.new(pat_params(group: group, user_types: [:human, :service_account])).execute
    elsif show_ssh_keys?
      ::KeysFinder.new({ users: users, key_type: 'ssh' }).execute
    elsif show_resource_access_tokens?
      PersonalAccessTokensFinder.new(pat_params(group: group, user_types: [:project_bot])).execute
    end
  end

  def pat_params(options)
    { **options,
      impersonation: false,
      sort: default_sort_order,
      **params.permit(*default_filters) }.with_indifferent_access
  end

  def notify_deleted_or_revoked_credential(credential)
    case credential
    when Key
      CredentialsInventoryMailer.ssh_key_deleted_email(
        params: {
          notification_email: credential.user.notification_email_or_default,
          title: credential.title,
          last_used_at: credential.last_used_at,
          created_at: credential.created_at
        }, deleted_by: current_user
      ).deliver_later
    when PersonalAccessToken
      CredentialsInventoryMailer.personal_access_token_revoked_email(token: credential, revoked_by: current_user).deliver_later
    end
  end

  def personal_access_token_finder
    return resource_access_token_finder if resource_type
    return group_personal_access_token_finder if revocable.instance_of?(Group)

    admin_personal_access_token_finder
  end

  def resource_access_token_finder
    PersonalAccessTokensFinder.new({ impersonation: false, users: bot_users })
  end

  def group_personal_access_token_finder
    ::PersonalAccessTokensFinder.new({ impersonation: false, users: users })
  end

  def admin_personal_access_token_finder
    ::PersonalAccessTokensFinder.new({ impersonation: false }, current_user)
  end

  def resource_type
    type = credentials_params[:resource_type]
    return unless type == "Group" || type == "Project"

    type.constantize
  end

  def revoke_service(token, resource_id: nil, resource_type: nil)
    return resource_access_token_revoke_service(token, resource_type, resource_id) if resource_id
    return group_personal_access_token_revoke_service(token, revocable) if revocable.instance_of?(Group)

    admin_personal_access_token_revoke_service(token)
  end

  def resource_access_token_revoke_service(token, resource_type, resource_id)
    ::ResourceAccessTokens::RevokeService.new(current_user, resource_type.find_by_id(resource_id), token)
  end

  def group_personal_access_token_revoke_service(token, group)
    ::PersonalAccessTokens::RevokeService.new(current_user, token: token, group: group)
  end

  def admin_personal_access_token_revoke_service(token)
    ::PersonalAccessTokens::RevokeService.new(current_user, token: token)
  end

  def users
    raise NotImplementedError, "#{self.class} does not implement #{__method__}"
  end

  def bot_users
    raise NotImplementedError, "#{self.class} does not implement #{__method__}"
  end

  def revocable
    raise NotImplementedError, "#{self.class} does not implement #{__method__}"
  end
end
