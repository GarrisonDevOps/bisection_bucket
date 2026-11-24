# frozen_string_literal: true

module GitlabSubscriptions
  class GroupsController < ApplicationController
    include ActionView::Helpers::SanitizeHelper

    layout 'minimal'

    before_action :authenticate_user!

    feature_category :subscription_management
    urgency :low

    def new
      @promo_code = subscription_params[:promo_code]
      @plan_type = sanitize(subscription_params[:plan_type])
      @tier = sanitize(subscription_params[:tier])

      if subscription_params[:plan_type]
        purchase_params = {
          plan_type: @plan_type,
          deployment_type: :gitlab_com,
          tier: @tier,
          **redirect_passthrough_params
        }.compact_blank

        @plan_data = {
          name: sanitize(subscription_params[:product_name]),
          purchase_link: {
            href: "#{subscription_portal_new_purchase_url}?#{purchase_params.to_query}"
          }
        }
      else
        @plan_data = find_plan

        return not_found unless @plan_data
      end

      @eligible_groups = GitlabSubscriptions::PurchaseEligibleNamespacesFinder.new(
        user: current_user,
        plan_id: @plan_data[:id],
        check_subscription_status: @plan_type.blank?
      ).execute
    end

    def create
      name = group_params[:name]
      path = Namespace.clean_path(group_params[:path] || name)

      response = Groups::CreateService.new(
        current_user, name: name, path: path, organization_id: Current.organization.id
      ).execute

      if response.success?
        render json: { id: response[:group].id }, status: :created
      else
        render json: { errors: response[:group]&.errors }, status: :unprocessable_entity
      end
    end

    private

    def group_params
      params.require(:group).permit(:name, :path, :visibility_level)
    end

    def subscription_params
      params.permit(:plan_id, :promo_code, :plan_type, :tier, :product_name)
    end

    # These attributes are forwarded to CustomersDot with the redirect to the purchase flow.
    def redirect_passthrough_params
      utm_keys = params.keys.select { |key| key.start_with?('utm_') } # rubocop:disable Rails/StrongParams -- params are permitted and sanitized in the next lines.

      permitted = params.permit(:entry_point, *utm_keys)

      permitted.transform_values { |value| sanitize(value) }.to_h
    end

    def find_plan
      return unless subscription_params[:plan_id]

      all_plans = GitlabSubscriptions::FetchSubscriptionPlansService.new(plan: :free).execute

      all_plans.find { |plan| plan[:id] == subscription_params[:plan_id] }
    end
  end
end
