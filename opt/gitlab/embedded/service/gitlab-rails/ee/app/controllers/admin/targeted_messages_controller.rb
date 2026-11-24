# frozen_string_literal: true

module Admin
  class TargetedMessagesController < Admin::ApplicationController
    feature_category :acquisition

    before_action :verify_targeted_messages_enabled!
    before_action :find_targeted_message, only: [:edit, :update, :destroy]

    def index
      @targeted_messages = Notifications::TargetedMessage.all
    end

    def new
      @targeted_message = Notifications::TargetedMessage.new
    end

    def create
      result = Notifications::TargetedMessages::CreateService.new(targeted_message_params).execute

      if result.success?
        flash[:notice] = s_('TargetedMessages|Targeted message was successfully created.')
        head :ok
      elsif result.reason == Notifications::TargetedMessages::CreateService::FOUND_INVALID_NAMESPACES
        targeted_message = result.payload
        flash[:alert] = result.message
        render json: {
          redirect_to: edit_admin_targeted_message_path(targeted_message)
        }, status: :ok
      else
        targeted_message = result.payload
        render json: { message: targeted_message.errors.messages }, status: :unprocessable_entity
      end
    end

    def edit; end

    def update
      result = Notifications::TargetedMessages::UpdateService.new(@targeted_message, targeted_message_params).execute

      if result.success?
        flash[:notice] = s_('TargetedMessages|Targeted message was successfully updated.')
        head :ok
      elsif result.reason == Notifications::TargetedMessages::UpdateService::FOUND_INVALID_NAMESPACES
        targeted_message = result.payload
        flash[:alert] = result.message
        render json: {
          redirect_to: edit_admin_targeted_message_path(targeted_message)
        }, status: :ok
      else
        targeted_message = result.payload
        render json: { message: targeted_message.errors.messages }, status: :unprocessable_entity
      end
    end

    def destroy
      Notifications::TargetedMessages::DestroyWorker.perform_async(@targeted_message.id) # rubocop:disable CodeReuse/Worker -- Extra service layer is not needed here

      redirect_to admin_targeted_messages_path,
        notice: format(s_('TargetedMessages|Scheduled deletion of targeted message with id: %{id}.'),
          id: @targeted_message.id)
    end

    private

    def find_targeted_message
      @targeted_message = Notifications::TargetedMessage.find(params.permit(:id)[:id])
    end

    def verify_targeted_messages_enabled!
      render_404 unless Feature.enabled?(:targeted_messages_admin_ui, :instance) &&
        ::Gitlab::Saas.feature_available?(:targeted_messages)
    end

    def targeted_message_params
      params.require(:targeted_message)
            .permit(:target_type, :starts_at, :ends_at, :namespace_ids_csv, roles: [])
            .reverse_merge!(roles: [])
    end
  end
end
