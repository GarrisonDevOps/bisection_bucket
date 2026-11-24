# frozen_string_literal: true

module GitlabSubscriptions
  module SelfManagedPurchaseRedirect
    extend ActiveSupport::Concern

    private

    def self_managed_purchase_redirect?(permitted_params)
      permitted_params[:plan_id].present? && permitted_params[:deployment_type] == 'self_managed'
    end

    def self_managed_purchase_credits_redirect?(permitted_params)
      permitted_params[:deployment_type] == 'self_managed' && permitted_params[:plan_type] == 'gitlab_credits'
    end

    def self_managed_purchase?(permitted_params)
      self_managed_purchase_redirect?(permitted_params) || self_managed_purchase_credits_redirect?(permitted_params)
    end
  end
end
