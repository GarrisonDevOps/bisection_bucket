# frozen_string_literal: true

class Groups::EpicsController < Groups::ApplicationController
  include IssuableActions
  include IssuableCollections
  include ToggleAwardEmoji
  include ToggleSubscriptionAction
  include EpicsActions
  include DescriptionDiffActions

  before_action :check_epics_available!
  before_action :epic, except: [:index, :new, :bulk_update]
  before_action :authorize_update_issuable!, only: :update
  before_action :authorize_create_epic!, only: [:new]
  before_action :verify_group_bulk_edit_enabled!, only: [:bulk_update]
  before_action :set_summarize_notes_feature_flag, only: :show
  after_action :log_epic_show, only: :show

  before_action do
    push_force_frontend_feature_flag(:glql_load_on_click, Banzai::FeatureFlags.glql_load_on_click_enabled?(@group))
  end

  feature_category :portfolio_management
  urgency :default, [:show, :new, :realtime_changes]
  urgency :low, [:discussions]
  def show
    respond_to do |format|
      format.html do
        redirect_to group_work_item_path(group, epic.work_item, params: request.query_parameters)
      end
      format.json do
        render json: serializer.represent(epic)
      end
    end
  end

  def new
    # rubocop:disable Rails/StrongParams -- forwards all remaining query params to the work item new page
    redirect_to group_work_item_new_url(
      group,
      params.except(
        :controller,
        :action,
        :group_id
      ).permit!
    )
    # rubocop:enable Rails/StrongParams
  end

  def index
    redirect_epics_to_work_items
  end

  private

  # rubocop: disable CodeReuse/ActiveRecord
  def epic_identifier_params
    params.permit(:epic_id, :id)
  end

  def epic_iid_param
    epic_identifier_params[:epic_id] || epic_identifier_params[:id]
  end

  def epic
    @issuable = @epic ||= @group.epics.find_by(iid: epic_iid_param)

    return render_404 unless can?(current_user, :read_work_item, @epic&.work_item)

    @noteable = @epic
  end
  # rubocop: enable CodeReuse/ActiveRecord
  alias_method :issuable, :epic
  alias_method :awardable, :epic
  alias_method :subscribable_resource, :epic

  def subscribable_project
    nil
  end

  def render_as_work_item
    @work_item = epic.work_item

    render 'work_items_index'
  end

  def epic_params
    params.require(:epic).permit(*epic_params_attributes)
  end

  def epic_params_attributes
    [
      :color,
      :title,
      :description,
      :start_date_fixed,
      :start_date_is_fixed,
      :due_date_fixed,
      :due_date_is_fixed,
      :state_event,
      :confidential,
      { label_ids: [],
        update_task: [:checked, :line_source, :line_sourcepos] }
    ]
  end

  def serializer
    EpicSerializer.new(current_user: current_user)
  end

  def discussion_serializer
    Epics::DiscussionSerializer.new(
      project: nil,
      noteable: issuable,
      current_user: current_user,
      note_entity: EpicNoteEntity
    )
  end

  def update_service
    ::WorkItems::LegacyEpics::UpdateService.new(group: @group, current_user: current_user,
      params: epic_params)
  end

  def sorting_field
    :epics_sort
  end

  def log_epic_show
    return unless current_user && @epic

    ::Gitlab::Search::RecentEpics.new(user: current_user).log_view(@epic)
    ::Gitlab::Search::RecentWorkItems.new(user: current_user).log_view(@epic.work_item)
  end

  def authorize_create_epic!
    render_404 unless can?(current_user, :create_epic, group)
  end

  def verify_group_bulk_edit_enabled!
    render_404 unless group.licensed_feature_available?(:group_bulk_edit)
  end

  def set_summarize_notes_feature_flag
    push_force_frontend_feature_flag(:summarize_comments, can?(current_user, :summarize_comments, epic))
  end

  def redirect_epics_to_work_items
    params = request.query_parameters.except("type", "type[]")

    epic_type = WorkItems::TypesFramework::Provider.new(@group).find_by_base_type(:epic)
    params = params.merge('type[]' => epic_type.id) if epic_type

    redirect_to group_work_items_path(group, params: params)
  end
end
