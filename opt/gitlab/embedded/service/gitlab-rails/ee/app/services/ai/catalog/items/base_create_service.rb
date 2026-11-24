# frozen_string_literal: true

module Ai
  module Catalog
    module Items
      class BaseCreateService < Ai::Catalog::BaseService
        ITEM_ATTRIBUTES = %i[name description visibility].freeze

        def execute
          return error_no_permissions unless allowed?

          validation_result = validate_before_save
          return validation_result if validation_result.error?

          item = Ai::Catalog::Item.new(item_params)
          item.build_new_version(version_params)

          return error_creating(item) unless save_item(item)

          track_ai_item_events('create_ai_catalog_item', tracking_properties_for(item, version: item.latest_version))
          send_audit_events(audit_event_name, item)

          ServiceResponse.success(payload: { item: item })
        end

        private

        def item_params
          params
            .slice(*ITEM_ATTRIBUTES)
            .merge(
              item_type: item_type,
              organization_id: project.organization_id,
              project_id: project.id
            )
        end

        def version_params
          {
            schema_version: schema_version,
            version: DEFAULT_VERSION,
            definition: definition,
            release_date: Time.zone.now,
            created_by: current_user
          }
        end

        def save_item(item)
          Ai::Catalog::Item.transaction do
            item.save!
            item.update!(latest_released_version: item.latest_version)
            true
          end
        rescue ActiveRecord::RecordInvalid
          false
        end

        def error_creating(item)
          error(item.errors.full_messages.presence)
        end

        def audit_event_name
          "create_ai_catalog_#{item_type}"
        end

        def definition
          raise NotImplementedError
        end

        def item_type
          raise NotImplementedError
        end

        def schema_version
          raise NotImplementedError
        end

        # Validates before saving, returning a ServiceResponse.error if validation
        # fails, otherwise a ServiceResponse.success.
        #
        # Override in subclasses with custom validations that are not in the model.
        #
        # @return [ServiceResponse]
        def validate_before_save
          ServiceResponse.success
        end
      end
    end
  end
end
