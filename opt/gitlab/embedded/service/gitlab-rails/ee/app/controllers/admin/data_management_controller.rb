# frozen_string_literal: true

module Admin
  class DataManagementController < Admin::ApplicationController
    feature_category :geo_replication
    urgency :low

    before_action :render_replicable_group_overview, only: :index
    before_action :model_found?

    authorize! :read_admin_data_management, only: [:index, :show]

    before_action :verify_replicable_model_enabled!, only: :index

    def index; end

    def show
      @model = model_class.find(model_params[:id])
    rescue ActiveRecord::RecordNotFound
      render_404
    end

    private

    # Runs before model_found? so a group slug (e.g. "uploads") still works when no model
    # resolves under that name. An enabled model with the same name wins, so the legacy
    # "uploads" page keeps working until it is removed.
    def render_replicable_group_overview
      requested_name = model_params[:model_name]
      return if requested_name.blank?

      models = ::Gitlab::Geo::ModelMapper.available_replicable_models
      return if models.any? { |model| ::Gitlab::Geo::ModelMapper.convert_to_name(model).pluralize == requested_name }

      @group_models = models.select { |model| model.replicator_class.replicable_group == requested_name }
      return if @group_models.empty?

      render :replicable_group
    end

    def model_found?
      return render_404 if singular_model_name?

      render_404 unless model_class
    end

    def verify_replicable_model_enabled!
      return if enabled_models.include?(model_class)

      redirect_to admin_data_management_path,
        notice: format(s_('Geo|Replication of %{replicable_title} is disabled on this site.'),
          replicable_title: model_class.replicator_class.replicable_title_plural)
    end

    def model_class
      @model_class ||= find_or_default_model_class
    end

    def find_or_default_model_class
      return default_model_class if model_name.blank?

      ::Gitlab::Geo::ModelMapper.find_from_name(model_name)
    end

    # Project is the default unless its replicator is disabled, to avoid a redirect loop
    def default_model_class
      enabled_models.include?(::Project) ? ::Project : enabled_models.first
    end

    def model_params
      params.permit(:model_name, :id)
    end

    def model_name
      @model_name ||= model_params[:model_name]&.singularize
    end

    def singular_model_name?
      model_name.present? && model_name == model_params[:model_name]
    end

    def enabled_models
      @enabled_models ||= ::Gitlab::Geo::ModelMapper.available_replicable_models
    end
  end
end
