# frozen_string_literal: true

class Admin::EmailsController < Admin::ApplicationController
  include Admin::EmailsHelper

  before_action :check_license_send_emails_from_admin_area_available!
  before_action :check_emails_rate_limit!, only: [:create]

  feature_category :not_owned # rubocop:todo Gitlab/AvoidFeatureCategoryNotOwned

  def show; end

  def create
    Admin::EmailService.new(email_params[:recipients], email_params[:subject], email_params[:body]).execute
    redirect_to admin_email_path, notice: _('Email sent')
  end

  private

  def email_params
    params.permit(:recipients, :subject, :body)
  end

  def check_emails_rate_limit!
    if admin_emails_are_currently_rate_limited?
      redirect_to admin_email_path, alert: _('Email could not be sent')
    end
  end

  def check_license_send_emails_from_admin_area_available!
    render_404 unless send_emails_from_admin_area_feature_available?
  end
end
