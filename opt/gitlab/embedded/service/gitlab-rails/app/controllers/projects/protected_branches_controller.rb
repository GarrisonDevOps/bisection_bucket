# frozen_string_literal: true

class Projects::ProtectedBranchesController < Projects::ProtectedRefsController
  skip_before_action :authorize_admin_protected_refs!
  # rubocop:disable Rails/LexicallyScopedActionFilter -- actions are defined in Projects::ProtectedRefsController
  before_action :authorize_create_protected_branch!, only: :create
  before_action :authorize_update_protected_branch!, only: [:index, :show, :update]
  before_action :authorize_delete_protected_branch!, only: :destroy
  # rubocop:enable Rails/LexicallyScopedActionFilter

  def show
    super

    render 'protected_branches/show'
  end

  protected

  def ref_type
    :branches
  end

  def project_refs
    @project.repository.branches
  end

  def service_namespace
    ::ProtectedBranches
  end

  def load_protected_ref
    @protected_ref = @project.protected_branches.find(params.permit(:id)[:id])
  end

  def access_levels
    [:merge_access_levels, :push_access_levels]
  end

  def protected_ref_params(*attrs)
    attrs = ([:name,
      :allow_force_push,
      { merge_access_levels_attributes: access_level_attributes,
        push_access_levels_attributes: access_level_attributes }] + attrs).uniq

    params.require(:protected_branch).permit(attrs)
  end

  def authorize_create_protected_branch!
    access_denied! unless can?(current_user, :create_protected_branch, project)
  end

  def authorize_update_protected_branch!
    access_denied! unless can?(current_user, :update_protected_branch, project)
  end

  def authorize_delete_protected_branch!
    access_denied! unless can?(current_user, :delete_protected_branch, project)
  end

  private

  def handle_gitaly_error(exception)
    Gitlab::ErrorTracking.track_exception(exception)

    @gitaly_unavailable = true

    render 'protected_branches/show', status: :service_unavailable
  end
end

Projects::ProtectedBranchesController.prepend_mod_with('Projects::ProtectedBranchesController')
