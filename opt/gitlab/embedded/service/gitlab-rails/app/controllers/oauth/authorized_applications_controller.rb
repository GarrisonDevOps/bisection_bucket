# frozen_string_literal: true

class Oauth::AuthorizedApplicationsController < Doorkeeper::AuthorizedApplicationsController
  include PageLayoutHelper

  layout 'profile'

  def index
    respond_to do |format|
      format.html { render "errors/not_found", layout: "errors", status: :not_found }
      format.json { render json: "", status: :not_found }
    end
  end

  def destroy
    if permitted_params[:token_id].present?
      current_resource_owner.oauth_authorized_tokens.find(permitted_params[:token_id].to_s).revoke
      return redirect_to user_settings_applications_url, status: :found, notice: revoked_notice
    end

    result = Authn::OauthApplications::RevokeService.new(
      current_user: current_resource_owner,
      application_id: permitted_params[:id].to_s
    ).execute

    if result.success?
      redirect_to user_settings_applications_url, status: :found, notice: revoked_notice
    else
      redirect_to user_settings_applications_url, status: :found, alert: result.message
    end
  end

  private

  def revoked_notice
    I18n.t(:notice, scope: [:doorkeeper, :flash, :authorized_applications, :destroy])
  end

  def permitted_params
    params.permit(:token_id, :id)
  end
end
