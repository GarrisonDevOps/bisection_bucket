# frozen_string_literal: true

module Users
  class TargetedMessageDismissalsController < ApplicationController
    feature_category :notifications

    before_action :verify_targeted_messages_enabled!

    def create
      id, namespace_id = params.require([:targeted_message_id, :namespace_id])

      dismissal = Notifications::TargetedMessageDismissal.new(
        user: current_user,
        targeted_message_id: id,
        namespace_id: namespace_id
      )

      if dismissal.save
        render json: { status: :success }, status: :created
      else
        render json: {}, status: :unprocessable_entity
      end
    end

    private

    def verify_targeted_messages_enabled!
      render_404 unless Feature.enabled?(:targeted_messages_admin_ui, :instance) &&
        ::Gitlab::Saas.feature_available?(:targeted_messages)
    end
  end
end
