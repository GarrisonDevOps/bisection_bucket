# frozen_string_literal: true

class Admin::LicensesController < Admin::ApplicationController
  include Admin::LicenseRequest

  before_action :license, only: [:download, :destroy]
  before_action :require_license, only: [:download, :destroy]

  respond_to :html

  feature_category :plan_provisioning
  urgency :low

  def create
    service_response = GitlabSubscriptions::UploadLicenseService.new(license_params, admin_subscription_path).execute
    @license = service_response.payload[:license]

    if service_response.success?
      flash[:notice] = service_response.message
      redirect_to admin_subscription_path
    else
      flash[:alert] = service_response.message
      redirect_to general_admin_application_settings_path
    end
  end

  def destroy
    Licenses::DestroyService.new(license, current_user).execute

    respond_to do |format|
      format.json do
        if License.current
          flash[:notice] = _('The license was removed. GitLab has fallen back on the previous license.')
        else
          flash[:alert] = _('The license was removed. GitLab now no longer has a valid license.')
        end

        render json: { success: true }
      end
    end
  end

  def sync_seat_link
    respond_to do |format|
      format.json do
        if Gitlab::SeatLinkData.new(refresh_token: true).sync
          render json: { success: true }
        else
          render json: { success: false }, status: :unprocessable_entity
        end
      end
    end
  end

  private

  def license_params
    license_params = params.require(:license).permit(:data_file, :data)
    license_params.delete(:data) if license_params[:data_file]
    license_params
  end
end
