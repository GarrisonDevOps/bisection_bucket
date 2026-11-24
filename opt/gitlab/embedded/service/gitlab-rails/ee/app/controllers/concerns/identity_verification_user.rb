# frozen_string_literal: true

module IdentityVerificationUser
  extend ActiveSupport::Concern
  include ::Gitlab::RackLoadBalancingHelpers

  private

  def find_verification_user
    return unless session[:verification_user_id].present?

    verification_user_id = session[:verification_user_id]
    load_balancer_stick_request(::User, :user, verification_user_id)
    User.find_by_id(verification_user_id)
  end
end
