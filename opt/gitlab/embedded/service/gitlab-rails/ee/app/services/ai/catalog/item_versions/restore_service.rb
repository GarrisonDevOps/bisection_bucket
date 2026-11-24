# frozen_string_literal: true

module Ai
  module Catalog
    module ItemVersions
      class RestoreService < Ai::Catalog::BaseService
        include Ai::Catalog::Concerns::DwsFlowConfigValidator

        def initialize(project:, current_user:, params: {})
          @source_version = params.delete(:source_version)
          @deprecate_current = params.fetch(:deprecate_current, false)
          super
        end

        def execute
          return error_feature_not_available unless feature_available?
          return error_source_not_present unless source_version.present?
          return error_no_permissions unless allowed?
          return error_source_not_released unless source_version.released?
          return error_source_deprecated if source_version.deprecated?
          return error_no_latest_version unless current_latest_version
          return error_source_is_current_latest if source_version == current_latest_version

          Ai::Catalog::Item.transaction do
            item.lock!
            version_to_deprecate = item.latest_released_version_with_fallback
            build_restored_version
            deprecate_version!(version_to_deprecate) if deprecate_current
            save_item!
          end

          track_ai_item_events('restore_ai_catalog_item',
            tracking_properties_for(item, version: new_version).merge(deprecated: deprecate_current.to_s)
          )
          send_audit_events('restore_ai_catalog_item', item,
            { source_version: source_version, new_version: new_version })

          ServiceResponse.success(payload: { item_version: new_version, item: item })
        rescue ActiveRecord::RecordInvalid => e
          error(e.record.errors.full_messages)
        end

        private

        attr_reader :source_version, :deprecate_current, :new_version

        def allowed?
          super && Ability.allowed?(current_user, :restore_ai_catalog_item, source_version)
        end

        def item
          source_version.item
        end

        def current_latest_version
          @current_latest_version ||= item.latest_released_version_with_fallback
        end

        def build_restored_version
          @new_version = item.build_new_version(
            definition: source_version.definition,
            schema_version: source_version.schema_version,
            version: item.next_version_number,
            release_date: Time.zone.now,
            created_by: current_user
          )

          set_dws_validated_on_version(@new_version) if item.custom_flow? || item.custom_agent?
          item.latest_released_version = new_version
        end

        def deprecate_version!(version)
          version.update!(deprecated: true)
        end

        def save_item!
          item.save!
        end

        def feature_available?
          Feature.enabled?(:ai_catalog_version_restore, current_user)
        end

        def error_feature_not_available
          error(s_('AICatalog|This feature is not available.'))
        end

        def error_source_not_present
          error(s_('AICatalog|You must provide a source version.'))
        end

        def error_source_not_released
          error(s_('AICatalog|Source version must be a released version.'))
        end

        def error_source_deprecated
          error(s_('AICatalog|Cannot restore a deprecated version.'))
        end

        def error_source_is_current_latest
          error(s_('AICatalog|Source version is already the current latest version.'))
        end

        def error_no_latest_version
          error(s_('AICatalog|Item must have a current latest released version to restore.'))
        end
      end
    end
  end
end
