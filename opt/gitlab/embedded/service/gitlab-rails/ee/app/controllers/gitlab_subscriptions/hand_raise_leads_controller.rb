# frozen_string_literal: true

module GitlabSubscriptions
  class HandRaiseLeadsController < ApplicationController
    before_action :verify_subscriptions_available!
    before_action :authenticate_user!
    before_action :verify_namespace!

    feature_category :acquisition
    urgency :low

    def create
      result = GitlabSubscriptions::CreateHandRaiseLeadService.new(user: current_user).execute(hand_raise_lead_params)

      if result.success?
        head :ok
      elsif result.reason == :rate_limited
        head :too_many_requests
      else
        render_403
      end
    end

    def track_cart_abandonment
      result = if cart_abandonment_params[:credits].present?
                 GitlabSubscriptions::TrackCartAbandonmentCreditsPurchaseService.new(
                   user: current_user,
                   namespace: namespace,
                   monthly_commitment_credits: cart_abandonment_params[:credits].to_i
                 ).execute
               else
                 GitlabSubscriptions::TrackCartAbandonmentService.new(
                   user: current_user,
                   namespace: namespace,
                   plan: cart_abandonment_params[:plan]
                 ).execute
               end

      if result.success?
        head :ok
      else
        render json: { message: result.message }, status: :unprocessable_entity
      end
    end

    private

    def authenticate_user!
      render_404 unless current_user
    end

    def hand_raise_lead_params
      base_params.merge(hand_raise_lead_extra_params)
    end

    def hand_raise_lead_extra_params
      {
        work_email: current_user.email,
        uid: current_user.id,
        provider: 'gitlab',
        setup_for_company: current_user.onboarding_status_setup_for_company,
        existing_plan: namespace.actual_plan_name,
        glm_source: 'gitlab.com'
      }
    end

    def base_params
      params.permit(
        :first_name, :last_name, :company_name, :phone_number, :country,
        :state, :namespace_id, :comment, :glm_content, :product_interaction
      )
    end

    def cart_abandonment_params
      params.permit(:plan, :credits)
    end

    def verify_subscriptions_available!
      render_404 unless ::Gitlab::Saas.feature_available?(:gitlab_com_subscriptions)
    end

    def verify_namespace!
      render_404 unless namespace
    end

    def namespace
      @namespace ||= if base_params[:namespace_id].present? && base_params[:namespace_id] != '0'
                       current_user.namespaces.find_by_id(base_params[:namespace_id])
                     end
    end
  end
end
