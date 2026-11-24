# frozen_string_literal: true

module Arkose
  module TokenVerifiable
    extend ActiveSupport::Concern

    private

    def verify_arkose_labs_token(user: nil, email: nil)
      Arkose::TokenVerificationService.new(
        session_token: token,
        user: user,
        email: email&.strip&.downcase,
        username: username,
        user_agent: request.user_agent
      ).execute
    end

    def token
      @token ||= permitted_params[:arkose_labs_token].to_s
    end

    def permitted_params
      params.permit(:arkose_labs_token)
    end
  end
end
