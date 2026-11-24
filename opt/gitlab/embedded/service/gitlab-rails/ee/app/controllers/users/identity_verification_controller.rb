# frozen_string_literal: true

module Users
  class IdentityVerificationController < BaseIdentityVerificationController
    before_action :require_unverified_user!, except: [:success]

    def show
      return if request.referer && URI.parse(request.referer).path == identity_verification_path

      session[:identity_verification_referer] = request.referer
    end

    def success
      redirect_to redirect_path
    end

    private

    def find_verification_user; end

    def redirect_path
      @redirect_path ||= session.delete(:identity_verification_referer) || root_path
    end

    def require_unverified_user!
      return unless @user.identity_verified?

      if html_request?
        redirect_to redirect_path
      else
        head :ok
      end
    end

    def required_params
      params.require(controller_name.to_sym)
    end
  end
end
