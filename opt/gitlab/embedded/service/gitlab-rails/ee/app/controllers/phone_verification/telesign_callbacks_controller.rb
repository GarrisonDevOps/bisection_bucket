# frozen_string_literal: true

# https://developer.telesign.com/enterprise/docs/transaction-callback-service
module PhoneVerification
  class TelesignCallbacksController < ApplicationController
    respond_to :json

    skip_before_action :authenticate_user!
    skip_before_action :verify_authenticity_token

    feature_category :instance_resiliency
    urgency :low

    def notify
      return not_found unless callback.valid?

      callback.log

      exempt_user_from_phone_number_verification if callback.payload.country_blocked?

      render json: {}
    end

    private

    def callback
      @callback ||= ::Telesign::TransactionCallback.new(request, callback_params)
    end

    # Must cover every path Telesign::TransactionCallbackPayload reads; anything
    # omitted here silently arrives as nil.
    def callback_params
      params.permit(:reference_id, status: [:code, :description, :updated_on], errors: [:code, :description])
    end

    def exempt_user_from_phone_number_verification
      user = callback.user

      return unless user
      return unless user.offer_phone_number_exemption?

      user.add_phone_number_verification_exemption
      Gitlab::EtagCaching::Store.new.touch(
        verification_state_signup_identity_verification_path,
        verification_state_identity_verification_path
      )

      Gitlab::AppLogger.info(
        message: 'Phone number verification exemption created',
        reason: 'Phone number country is blocked in Telesign',
        username: user.username
      )
    end
  end
end
