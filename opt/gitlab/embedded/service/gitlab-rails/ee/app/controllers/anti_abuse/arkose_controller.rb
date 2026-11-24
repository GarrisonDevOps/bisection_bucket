# frozen_string_literal: true

module AntiAbuse
  class ArkoseController < ApplicationController
    include IdentityVerificationUser

    feature_category :instance_resiliency

    skip_before_action :authenticate_user!
    before_action :require_signed_in_user!

    def data_exchange_payload
      render json: { payload: helpers.arkose_data_exchange_payload(use_case, email: @user&.email) }
    end

    private

    def use_case
      if @user.arkose_verified?
        Arkose::DataExchangePayload::USE_CASE_IDENTITY_VERIFICATION
      else
        Arkose::DataExchangePayload::USE_CASE_SIGN_UP
      end
    end

    def require_signed_in_user!
      @user = find_verification_user || current_user

      head :unauthorized unless @user
    end
  end
end
