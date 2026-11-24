# frozen_string_literal: true

module ArkoseHelper
  def arkose_data_exchange_payload(use_case, email: nil)
    show_challenge =
      if use_case == Arkose::DataExchangePayload::USE_CASE_SIGN_UP
        ::Gitlab::ApplicationRateLimiter.peek(:hard_phone_verification_transactions_limit, scope: { scope: :global })
      else
        use_case == Arkose::DataExchangePayload::USE_CASE_IDENTITY_VERIFICATION
      end

    Arkose::DataExchangePayload.new(
      request,
      use_case: use_case,
      email: email,
      require_challenge: show_challenge
    ).build
  end
end
