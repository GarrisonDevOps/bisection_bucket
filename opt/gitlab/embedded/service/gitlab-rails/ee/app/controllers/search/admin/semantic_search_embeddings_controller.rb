# frozen_string_literal: true

module Search
  module Admin
    class SemanticSearchEmbeddingsController < ::Admin::ApplicationController
      include ::Ai::ActiveContext::Concerns::Loggable

      feature_category :global_search
      urgency :low

      before_action :redirect_if_semantic_search_unavailable
      before_action :collection_key,
        only: [:show, :update, :test_model_configuration, :update_embeddings_request_batch_size]
      before_action :redirect_if_collection_unavailable,
        only: [:show, :update, :test_model_configuration, :update_embeddings_request_batch_size]
      before_action :redirect_unless_feature_setting_allowed,
        only: [:show, :update, :test_model_configuration, :update_embeddings_request_batch_size]
      before_action :fetch_user_update_ability,
        only: [:show, :update, :test_model_configuration, :update_embeddings_request_batch_size]
      before_action :fetch_self_hosted_embedding_models, only: [:show, :update]

      COLLECTION_CLASS_LOOKUP = {
        code: ::Ai::ActiveContext::Collections::Code
      }.freeze

      def show
        build_presenter

        return unless validate_user_can_update(flash_type: :notice)
        return unless collection_record.next_indexing_embedding_model

        flash.now[:notice] = "You cannot update the model at this time. " \
          "There is already a next embedding model."
      end

      def update
        pre_update_checks_satisfied = validate_user_can_update && require_model_metadata_params

        fetch_tested_model_metadata_from_params

        update_embedding_model if pre_update_checks_satisfied

        build_presenter(@model_metadata_params, @tested_model_metadata, force_expand_embedding_model_form: true)

        render :show
      end

      def test_model_configuration
        unless validate_user_can_update
          return render json: { success: false, message: flash[:alert] }, status: :unauthorized
        end

        unless require_model_metadata_params(exclude_batch_size: true)
          return render json: { success: false, message: flash[:alert] }, status: :bad_request
        end

        response = test_embedding_model

        if response.error?
          return render json: { success: false, message: response.message }, status: :unprocessable_entity
        end

        render json: { success: true, tested_model_metadata: response.payload[:tested_model_metadata] }
      end

      def update_embeddings_request_batch_size
        unless validate_user_can_update
          return render json: { success: false, message: flash[:alert] }, status: :unauthorized
        end

        batch_size = params.permit(:batch_size)[:batch_size].presence&.to_i
        for_next_model = Gitlab::Utils.to_boolean(
          params.permit(:for_next_model)[:for_next_model], default: false
        )

        response = ::Ai::ActiveContext::UpdateEmbeddingsRequestBatchSizeService.new(
          collection_class: collection_class,
          batch_size: batch_size,
          for_next_model: for_next_model
        ).execute

        if response.error?
          return render json: { success: false, message: response.message }, status: :unprocessable_entity
        end

        render json: { success: true, embeddings_request_batch_size: batch_size }
      rescue ActionController::ParameterMissing => e
        render json: { success: false, message: "Error: #{e.message}." }, status: :bad_request
      end

      private

      def collection_key
        @collection_key = params.require(:id).to_sym
      end

      def collection_class
        COLLECTION_CLASS_LOOKUP[@collection_key]
      end

      def collection_record
        @collection_record ||= collection_class&.collection_record
      end

      def redirect_if_semantic_search_unavailable
        if ::Ai::ActiveContext.semantic_search_available? &&
            ::ActiveContext.adapter&.connection.present?
          return
        end

        redirect_to search_admin_application_settings_path
      end

      def redirect_if_collection_unavailable
        return if collection_record.present?

        redirect_to search_admin_application_settings_path
      end

      def redirect_unless_feature_setting_allowed
        return if ::Ai::ActiveContext::Embedding.feature_setting_allowed?(collection_record.name_without_prefix)

        redirect_to search_admin_application_settings_path
      end

      def fetch_user_update_ability
        @instance_allows_user_model_selection = ::Ai::ActiveContext.user_selects_embedding_model?
        @user_has_update_model_permissions = Ability.allowed?(current_user, :manage_instance_model_selection)
      end

      def fetch_self_hosted_embedding_models
        @self_hosted_embedding_models = ::Ai::ActiveContext::Embedding.self_hosted_models
      end

      def build_presenter(
        model_metadata_params = nil, tested_model_metadata = nil, force_expand_embedding_model_form: false)
        presenter_params = {
          instance_allows_user_model_selection: @instance_allows_user_model_selection,
          user_has_update_model_permissions: @user_has_update_model_permissions,
          collection_record: collection_record.reset,
          force_expand_embedding_model_form: force_expand_embedding_model_form
        }
        presenter_params[:model_metadata_params] = model_metadata_params if model_metadata_params
        presenter_params[:tested_model_metadata] = tested_model_metadata if tested_model_metadata

        @presenter = SemanticSearchEmbeddingsPresenter.new(
          **presenter_params
        )
      end

      def validate_user_can_update(flash_type: :alert)
        unless @instance_allows_user_model_selection
          flash.now[flash_type] = "Model selection by user is not available in this GitLab instance."
          return false
        end

        unless @user_has_update_model_permissions
          flash.now[flash_type] = "You do not have sufficient permissions to update the model."
          return false
        end

        true
      end

      def require_model_metadata_params(exclude_batch_size: false)
        model_details = params.require(:embedding_model).split("__")
        embedding_dimensions = params.require(:embedding_dimensions)

        @model_metadata_params = {
          model_type: model_details.first.to_sym,
          model_ref: model_details.second.to_s,
          dimensions: embedding_dimensions.to_i
        }

        unless exclude_batch_size
          @model_metadata_params[:embeddings_request_batch_size] = params.permit(
            :embeddings_request_batch_size
          )[:embeddings_request_batch_size].presence&.to_i
        end

        true
      rescue ActionController::ParameterMissing => e
        flash.now[:alert] = "Error: #{e.message}."
        false
      end

      def chunk_strategy_params
        permitted = params.permit(:chunk_strategy, :chunk_strategy_size)
        {
          chunk_strategy: permitted[:chunk_strategy].presence,
          chunk_strategy_size: permitted[:chunk_strategy_size].presence&.to_i
        }
      end

      def fetch_tested_model_metadata_from_params
        metadata_json = params.permit(:tested_model_metadata)[:tested_model_metadata]
        return if metadata_json.blank?

        parsed_metadata = Gitlab::Json.safe_parse(metadata_json)

        @tested_model_metadata = {
          model_type: parsed_metadata['model_type'].to_sym,
          model_ref: parsed_metadata['model_ref'].to_s,
          dimensions: parsed_metadata['dimensions'].to_i
        }
      end

      def test_embedding_model
        ::Ai::ActiveContext::TestEmbeddingModelService.new(
          collection_class: collection_class,
          user: current_user,
          **@model_metadata_params
        ).execute
      rescue StandardError => e
        logger.error(
          build_structured_payload(
            collection: @collection_key,
            error_class: e.class.name,
            message: e.message,
            **@model_metadata_params
          )
        )

        ServiceResponse.error(message: 'unknown error')
      end

      def update_embedding_model
        skip_embeddings_request_test = (
          @model_metadata_params.except(:embeddings_request_batch_size) == @tested_model_metadata
        )

        ::Ai::ActiveContext::EmbeddingModelActivationService.new(
          collection_class: collection_class,
          skip_embeddings_request_test: skip_embeddings_request_test,
          user: current_user,
          **@model_metadata_params,
          **chunk_strategy_params
        ).execute!

        flash_update_successful
      rescue StandardError => e
        logger.error(
          build_structured_payload(
            collection: @collection_key,
            error_class: e.class.name,
            message: e.message,
            **@model_metadata_params
          )
        )

        flash_update_failed(e)
      end

      def flash_update_successful
        unless collection_record.current_indexing_embedding_model
          return flash.now[:notice] = 'Embedding model has been set.'
        end

        flash.now[:notice] = 'Embeddings updated and backfill started.'
      end

      def flash_update_failed(error)
        error_detail = error.message if error.is_a?(::Ai::ActiveContext::ServiceErrors::Error)
        if error.is_a?(::Ai::ActiveContext::EmbeddingModelActivationService::BatchSizeOnlyUpdateError)
          error_detail = "#{error_detail}, please use the dedicated batch size update form"
        end

        error_detail ||= 'unknown error'

        flash.now[:alert] = "Update failed: #{error_detail}."
      end
    end
  end
end
