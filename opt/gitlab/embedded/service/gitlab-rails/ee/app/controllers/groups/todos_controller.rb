# frozen_string_literal: true

class Groups::TodosController < Groups::ApplicationController
  include Gitlab::Utils::StrongMemoize
  include TodosActions

  before_action :authenticate_user!, only: [:create]

  feature_category :portfolio_management

  private

  def issuable
    strong_memoize(:epic) do
      next if todo_target_params[:issuable_type] != 'epic'

      EpicsFinder.new(current_user, group_id: @group.id).find(todo_target_params[:issuable_id])
    end
  end

  def todo_target_params
    params.permit(:issuable_type, :issuable_id)
  end
  strong_memoize_attr :todo_target_params
end
