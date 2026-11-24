# frozen_string_literal: true

module API
  module Admin
    class DataManagement < ::API::Base
      include PaginationParams
      include APIGuard

      feature_category :geo_replication
      urgency :low

      VERIFICATION_STATES = %w[pending started succeeded failed disabled].freeze

      before do
        authenticated_as_admin!
      end

      helpers do
        def verifiable?(model_class)
          return false unless ::Gitlab::Geo.enabled?
          return false unless model_class.respond_to?(:replicator_class)

          model_class.replicator_class.verification_enabled?
        end

        def find_model_from_record_identifier(identifier, model_class)
          primary_key_value = if identifier.is_a?(Integer)
                                identifier
                              else
                                decoded_string = Base64.urlsafe_decode64(identifier)
                                bad_request!('Invalid composite key format') unless decoded_string.include?(' ')

                                decoded_string.split(' ')
                              end

          model_class.find_by_primary_key(primary_key_value)
        rescue ArgumentError, TypeError => e
          bad_request!(e)
        end

        def find_verifiable_model_class
          model_class = Gitlab::Geo::ModelMapper.find_from_name(singular_model_name)
          not_found!(params[:model_name]) unless model_class
          bad_request!("#{model_class} is not a verifiable model.") unless verifiable?(model_class)

          model_class
        end

        def decoded_identifiers(identifier_array)
          return identifier_array if identifier_array.all?(Integer)

          identifier_array.map do |identifier|
            decoded_string = Base64.urlsafe_decode64(identifier)
            bad_request!('Invalid composite key format') unless decoded_string.include?(' ')

            decoded_string.split(' ')
          end
        rescue ArgumentError, TypeError => e
          bad_request!(e)
        end

        def singular_model_name
          params[:model_name].singularize
        end
      end
      # rubocop:disable API/ParameterValuesProc -- model_name generated dynamic values at runtime
      resource :admin do
        resource :data_management do
          route_setting :lifecycle, :experiment
          route_param :model_name, type: String, desc: 'The name of the model being requested' do
            route_param :record_identifier,
              types: [Integer, String],
              desc: 'The identifier of the model being requested' do
              # Example request:
              #   GET /admin/data_management/:model_name/:record_identifier
              desc 'Retrieve information about a model record' do
                summary 'Retrieve data about the requested model record identifier'
                detail 'Retrieves information about a specified model record. Only available to administrators.'
                success code: 200, model: Entities::Admin::Model
                failure [
                  { code: 400, message: '400 Bad request' },
                  { code: 401, message: '401 Unauthorized' },
                  { code: 403, message: '403 Forbidden' },
                  { code: 404, message: '404 Model Not Found' }
                ]
                tags %w[data_management]
              end
              params do
                requires :model_name,
                  type: String,
                  values: -> { Gitlab::Geo::ModelMapper.available_model_names_pluralized },
                  documentation: { type: 'string', example: 'uploads' },
                  desc: 'See https://docs.gitlab.com/administration/admin_area/#data-management ' \
                    'for the list of allowed values'
                requires :record_identifier, types: [Integer, String], desc: 'Unique identifier of the record. ' \
                                                                         'Can be an integer or a ' \
                                                                         'Base64-encoded string, as returned ' \
                                                                         'by the list endpoint.'
              end

              route_setting :lifecycle, :experiment
              route_setting :tier, :premium
              route_setting :authorization, permissions: :read_admin_data_management, boundary_type: :instance,
                assignable_when: [:admin]
              get do
                model_class = Gitlab::Geo::ModelMapper.find_from_name(singular_model_name)
                not_found!(params[:model_name]) unless model_class

                model = find_model_from_record_identifier(params[:record_identifier], model_class)
                not_found!(params[:record_identifier]) unless model

                present model, with: Entities::Admin::Model
              end

              # Example request:
              #   PUT /admin/data_management/:model_name/:record_identifier/checksum
              desc 'Recalculate the checksum of a model record' do
                summary 'Recalculate the checksum of the requested model record identifier'
                detail 'Recalculates the checksum of a specified model record. The checksum value is a ' \
                  'representation of the queried model hashed with the md5 or sha256 algorithm. Only available to ' \
                  'administrators on primary Geo sites.'
                success code: 200, model: Entities::Admin::Model
                failure [
                  { code: 400, message: '400 Bad request' },
                  { code: 401, message: '401 Unauthorized' },
                  { code: 403, message: '403 Forbidden' },
                  { code: 404, message: '404 Model Not Found' }
                ]
                tags %w[data_management]
              end
              params do
                requires :model_name,
                  type: String,
                  values: -> { Gitlab::Geo::ModelMapper.available_model_names_pluralized },
                  documentation: { type: 'string', example: 'uploads' },
                  desc: 'See https://docs.gitlab.com/administration/admin_area/#data-management ' \
                    'for the list of allowed values'
                requires :record_identifier, type: Integer, desc: 'Unique identifier of the record, as returned ' \
                                                              'by the list endpoint.'
              end

              route_setting :lifecycle, :experiment
              route_setting :tier, :premium
              route_setting :authorization, permissions: :update_admin_data_management, boundary_type: :instance,
                assignable_when: [:admin]
              put 'checksum' do
                bad_request!('Endpoint only available on primary site.') unless ::Gitlab::Geo.primary?

                model_class = find_verifiable_model_class
                model = find_model_from_record_identifier(params[:record_identifier], model_class)
                not_found!(params[:record_identifier]) unless model

                model.replicator.verify

                if model.verification_state_object.verification_failed?
                  bad_request!("Verifying #{params[:model_name]}/#{params[:record_identifier]} failed.")
                end

                present model, with: Entities::Admin::Model
              end
            end

            # Example request:
            #   GET /admin/data_management/:model_name
            desc 'Retrieve model information' do
              summary 'Retrieve all records of the requested model'
              detail 'Retrieves information about a data model in an instance. Only available to administrators.'
              success code: 200, model: Entities::Admin::Model
              failure [
                { code: 400, message: '400 Bad request' },
                { code: 401, message: '401 Unauthorized' },
                { code: 403, message: '403 Forbidden' },
                { code: 404, message: '404 Model Not Found' }
              ]
              is_array true
              tags %w[data_management]
            end
            params do
              use :pagination
              requires :model_name,
                type: String,
                values: -> { Gitlab::Geo::ModelMapper.available_model_names_pluralized },
                documentation: { type: 'string', example: 'uploads' },
                desc: 'See https://docs.gitlab.com/administration/admin_area/#data-management ' \
                  'for the list of allowed values'
              optional :identifiers, types: [Array[Integer], Array[String]], desc: 'Filter results with an array of ' \
                                                                               'unique identifiers of the ' \
                                                                               'requested model, which can be ' \
                                                                               'integers or base64 encoded ' \
                                                                               'strings.'
              optional :checksum_state,
                type: String,
                desc: 'Filter by checksum status.',
                values: VERIFICATION_STATES
              optional :cursor, type: String, desc: 'Cursor for obtaining the next set of records.'
              optional :sort, type: String, values: %w[asc desc], default: 'asc', desc: 'Sort results in ' \
                                                                                    'ascending or descending ' \
                                                                                    'order.'
            end
            route_setting :lifecycle, :experiment
            route_setting :tier, :premium
            route_setting :authorization, permissions: :read_admin_data_management, boundary_type: :instance,
              assignable_when: [:admin]
            get do
              model_class = Gitlab::Geo::ModelMapper.find_from_name(singular_model_name)
              not_found!(params[:model_name]) unless model_class

              relation = model_class.respond_to?(:with_state_details) ? model_class.with_state_details : model_class
              if params[:identifiers]&.compact.present?
                relation = relation.primary_key_in(decoded_identifiers(params[:identifiers]))
              end

              if params[:checksum_state].present?
                bad_request!("#{model_class} is not a verifiable model.") unless verifiable?(model_class)
                relation = relation.with_verification_state(:"verification_#{params[:checksum_state]}")
              end

              if params[:pagination] == 'keyset'
                # the order_by parameter's default value is the primary key column of the model -
                # using the first column for composite keys
                model_pk = model_class.primary_key
                params[:order_by] = model_pk.is_a?(Array) ? model_pk.first : model_pk

                present paginate_with_strategies(relation.keyset_order_by_primary_key(params[:sort])),
                  with: Entities::Admin::Model
              else
                present paginate(relation.order_by_primary_key), with: Entities::Admin::Model
              end
            end

            # Example request:
            #   PUT /admin/data_management/:model_name/checksum
            desc 'Recalculate checksums for model records' do
              summary 'Marks all records from a given model for checksum recalculation'
              detail 'Recalculates checksums for selected records of a specified model, filtered by `checksum_state` ' \
                'and `identifiers` parameters if provided. The request enqueues a background job to perform the ' \
                'recalculation. Only available to administrators on primary Geo sites.'
              success code: 200, model: Entities::Admin::Model
              failure [
                { code: 400, message: '400 Bad request' },
                { code: 401, message: '401 Unauthorized' },
                { code: 403, message: '403 Forbidden' },
                { code: 404, message: '404 Model Not Found' }
              ]
              tags %w[data_management]
            end
            params do
              requires :model_name,
                type: String,
                values: -> { Gitlab::Geo::ModelMapper.available_model_names_pluralized },
                documentation: { type: 'string', example: 'uploads' },
                desc: 'See https://docs.gitlab.com/administration/admin_area/#data-management ' \
                  'for the list of allowed values'
              optional :identifiers, types: [Array[Integer], Array[String]], desc: 'Filter results with an array of ' \
                                                                               'unique identifiers of the ' \
                                                                               'requested model, which can be ' \
                                                                               'integers or base64 encoded ' \
                                                                               'strings.'
              optional :checksum_state,
                type: String,
                desc: 'Filter by checksum status.',
                values: VERIFICATION_STATES.excluding('pending')
            end
            route_setting :lifecycle, :experiment
            route_setting :tier, :premium
            route_setting :authorization, permissions: :update_admin_data_management, boundary_type: :instance,
              assignable_when: [:admin]
            put 'checksum' do
              bad_request!('Endpoint only available on primary site.') unless ::Gitlab::Geo.primary?
              model_class = find_verifiable_model_class

              service_params = {}
              if params[:identifiers]&.compact.present?
                # The service accepts the IDs of the state records, so we convert the passed model IDs
                # into the matching state record IDs
                model_records = model_class.with_state_details.primary_key_in(decoded_identifiers(params[:identifiers]))
                state_records_ids = model_records.map { |model_record| model_record.verification_state_object.id }
                service_params[:identifiers] = state_records_ids
              end

              if params[:checksum_state].present?
                service_params[:checksum_state] = "verification_#{params[:checksum_state]}"
              end

              no_matching_records = service_params.key?(:identifiers) && service_params[:identifiers].empty?

              result = if no_matching_records
                         { status: 'success', message: 'No records matched the given identifiers.' }
                       else
                         service_result = ::Geo::BulkPrimaryVerificationService
                           .new(model_class.name, service_params).async_execute

                         if service_result.success?
                           { status: 'success', message: service_result.message }
                         else
                           { status: 'error', message: service_result.message }
                         end
                       end

              present result
            end
          end
        end
      end
      # rubocop:enable API/ParameterValuesProc
    end
  end
end
