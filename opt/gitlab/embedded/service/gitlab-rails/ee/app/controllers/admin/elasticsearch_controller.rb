# frozen_string_literal: true

class Admin::ElasticsearchController < Admin::ApplicationController
  feature_category :global_search
  urgency :low

  # POST
  # Scheduling indexing jobs
  def enqueue_index
    ::Search::Elastic::ReindexingService.execute

    flash[:notice] =
      _('Advanced search indexing in progress. It might take a few minutes to create indices and initiate indexing. ' \
        'Please use gitlab:elastic:info rake task to check progress.')

    redirect_to redirect_path
  end

  # POST
  # Trigger reindexing task
  def trigger_reindexing
    if Search::Elastic::ReindexingTask.running?
      flash[:warning] = _('Elasticsearch reindexing is already in progress')
    else
      @elasticsearch_reindexing_task = Search::Elastic::ReindexingTask.new(trigger_reindexing_params)
      if @elasticsearch_reindexing_task.save
        flash[:notice] = _('Elasticsearch reindexing triggered')
      else
        errors = @elasticsearch_reindexing_task.errors.full_messages.join(', ')
        flash[:alert] = format(_("Elasticsearch reindexing was not started: %{errors}"), errors: errors)
      end
    end

    redirect_to redirect_path(anchor: 'js-elasticsearch-reindexing')
  end

  # POST
  # Cancel index deletion after a successful reindexing operation
  def cancel_index_deletion
    task = Search::Elastic::ReindexingTask.find(cancel_index_deletion_params[:task_id])
    task.update!(delete_original_index_at: nil)

    flash[:notice] = _('Index deletion is canceled')

    redirect_to redirect_path(anchor: 'js-elasticsearch-reindexing')
  end

  # POST
  # Retry a halted migration
  def retry_migration
    migration = Elastic::DataMigrationService[retry_migration_params[:version].to_i]

    Search::Elastic::Helper.default.delete_migration_record(migration)
    Elastic::DataMigrationService.drop_migration_halted_cache!(migration)

    flash[:notice] = _('Migration has been scheduled to be retried')

    redirect_to redirect_path
  end

  private

  def redirect_path(anchor: 'js-elasticsearch-settings')
    search_admin_application_settings_path(anchor: anchor)
  end

  def cancel_index_deletion_params
    params.permit(:task_id)
  end

  def retry_migration_params
    params.permit(:version)
  end

  def trigger_reindexing_params
    permitted_params = params.require(:search_elastic_reindexing_task).permit(:elasticsearch_max_slices_running,
      :elasticsearch_slice_multiplier)
    trigger_reindexing_params = {}
    if permitted_params.has_key?(:elasticsearch_max_slices_running)
      trigger_reindexing_params[:max_slices_running] =
        permitted_params[:elasticsearch_max_slices_running]
    end

    if permitted_params.has_key?(:elasticsearch_slice_multiplier)
      trigger_reindexing_params[:slice_multiplier] =
        permitted_params[:elasticsearch_slice_multiplier]
    end

    trigger_reindexing_params
  end
end
