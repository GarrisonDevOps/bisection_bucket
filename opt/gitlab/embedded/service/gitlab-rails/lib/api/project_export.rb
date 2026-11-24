# frozen_string_literal: true

module API
  class ProjectExport < ::API::Base
    feature_category :importers
    urgency :low
    helpers Helpers::BulkImports::AuditHelpers

    params do
      requires :id, types: [String, Integer], desc: 'ID or URL-encoded path of the project.'
    end
    resource :projects, requirements: { id: %r{[^/]+} } do
      resource do
        before do
          not_found! unless Gitlab::CurrentSettings.project_export_enabled?

          authorize_admin_project
        end

        desc 'Retrieve the status of a project export' do
          detail 'Retrieves the status of the most recent export for a specified project. The `export_status` is ' \
            'one of: `none` when no exports are queued, started, finished, or being regenerated; `queued` when ' \
            'the export request is received and is in the queue to be processed; `started` when the export is in ' \
            'progress, including actions on the resulting file such as sending the notification email or ' \
            'uploading it to a web server; `finished` when the export is complete and the user was notified; ' \
            '`failed` when the export failed; or `regeneration_in_progress` when an export file is available to ' \
            'download and a new export is in progress. The `_links` object is returned only when the export is ' \
            'finished. The `created_at` attribute is the project creation time, not the export start time.'
          success code: 200, model: Entities::ProjectExportStatus
          failure [
            { code: 401, message: 'Unauthorized' },
            { code: 403, message: 'Forbidden' },
            { code: 404, message: 'Not found' },
            { code: 503, message: 'Service unavailable' }
          ]
          tags ['project_import']
        end
        route_setting :authorization, permissions: :read_project_export, boundary_type: :project
        get ':id/export' do
          present user_project, with: Entities::ProjectExportStatus, current_user: current_user
        end

        desc 'Download a project export' do
          detail 'Downloads the most recent export of a specified project.'
          success code: 200
          failure [
            { code: 401, message: 'Unauthorized' },
            { code: 403, message: 'Forbidden' },
            { code: 404, message: 'Not found' },
            { code: 503, message: 'Service unavailable' }
          ]
          tags ['project_import']
          produces %w[application/octet-stream application/json]
        end
        route_setting :authorization, permissions: :download_project_export, boundary_type: :project
        get ':id/export/download' do
          check_rate_limit! :project_download_export, scope: { user: current_user, project: user_project }

          if user_project.export_file_exists?(current_user)
            if user_project.export_archive_exists?(current_user)
              export_file = user_project.export_file(current_user)
              present_carrierwave_file!(
                export_file,
                content_disposition: 'attachment',
                content_type: Gitlab::ImportExport.export_download_content_type
              )
            else
              render_api_error!('The project export file is not available yet', 404)
            end
          else
            render_api_error!('404 Not found or has expired', 404)
          end
        end

        desc 'Export a project' do
          detail 'Exports a project. Use the `upload` hash parameter to upload the exported project to a web server ' \
            'or any S3-compatible platform. Uploads support only binary data and are sent with the ' \
            '`Content-Type: application/gzip` header, so a pre-signed upload URL must include this header in its ' \
            'signature. The export can take some time, so the upload URL must not have a short expiration time. ' \
            'Because of a known issue, uploads to Amazon S3 cannot be larger than 5 GB. The maximum export file ' \
            'size is set by an administrator with the `max_export_size` application setting. Default is `0` ' \
            '(unlimited).'
          success code: 202
          failure [
            { code: 400, message: 'Bad request' },
            { code: 401, message: 'Unauthorized' },
            { code: 403, message: 'Forbidden' },
            { code: 404, message: 'Not found' },
            { code: 429, message: 'Too many requests' },
            { code: 503, message: 'Service unavailable' }
          ]
          tags ['project_import']
        end
        params do
          optional :description, type: String, desc: 'Overrides the project description.'
          optional :upload, type: Hash, desc: 'Details for uploading the exported project to a web server.' do
            optional :url, type: String, desc: 'URL to upload the exported project to.'
            optional :http_method, type: String, default: 'PUT', values: %w[PUT POST],
              desc: 'HTTP method to upload the exported project.'
          end
          optional :excluded_relations, type: Array[String],
            desc: 'Project relation names to exclude from the export, for example `merge_requests`, `issues`, ' \
              '`ci_pipelines`, `uploads`, `lfs_objects`, `avatar`, and `wiki_repository`. Other valid names are ' \
              'the relation names under `tree.project` or `ee.tree.project` in ' \
              '`lib/gitlab/import_export/project/import_export.yml`. Use it to reduce the size of an export or to ' \
              'avoid timeouts. Excluded relations are not added to the archive and cannot be imported. You cannot ' \
              'exclude `project`, because the import of the archive fails, or `repository`, ' \
              '`snippets_repository`, and `design_repository`, because the archive restores a broken project. ' \
              'Invalid names return an error that lists them, for example ' \
              '`Invalid excluded_relations: repository`. ' \
              '[Introduced](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/226480) in GitLab 18.11.'
        end
        route_setting :authorization, permissions: :create_project_export, boundary_type: :project
        post ':id/export' do
          check_rate_limit! :project_export, scope: { user: current_user }

          if params[:excluded_relations].present?
            invalid = params[:excluded_relations] -
              ::Projects::ImportExport::RelationExport.excludable_relation_names

            render_api_error!("Invalid excluded_relations: #{invalid.join(', ')}", 400) if invalid.any?
          end

          user_project.remove_export_for_user(current_user)

          project_export_params = declared_params(include_missing: false)
          after_export_params = project_export_params.delete(:upload) || {}

          export_strategy = if after_export_params[:url].present?
                              params = after_export_params.slice(:url, :http_method).symbolize_keys

                              Import::AfterExportStrategies::WebUploadStrategy.new(**params)
                            end

          if export_strategy&.invalid?
            render_validation_error!(export_strategy)
          else
            begin
              user_project.add_export_job(current_user: current_user,
                after_export_strategy: export_strategy,
                params: project_export_params)
            rescue Project::ExportLimitExceeded, Project::ExportAlreadyInProgress => e
              render_api_error!(e.message, 400)
            end
          end

          accepted!
        end
      end

      resource do
        before do
          not_found! unless Gitlab::CurrentSettings.bulk_import_enabled?

          authorize_admin_project
        end

        desc 'Schedule a relations export for a project' do
          detail 'Schedules a relations export for a specified project. By default, this endpoint is limited to 6 ' \
            'requests per minute for each user and project. ' \
            'The instance must meet the direct transfer prerequisites, including the `bulk_import_enabled` ' \
            'application setting. If the setting is disabled, a `404` is returned. This endpoint cannot be used ' \
            'with the file-based group import and export API.'
          success code: 202
          failure [
            { code: 400, message: 'Bad request' },
            { code: 401, message: 'Unauthorized' },
            { code: 403, message: 'Forbidden' },
            { code: 404, message: 'Not found' },
            { code: 429, message: 'Too many requests' },
            { code: 503, message: 'Service unavailable' }
          ]
          tags ['project_import']
        end
        params do
          optional :batched, type: Boolean, desc: 'If `true`, exports in batches.'
        end
        route_setting :authorization, permissions: :create_project_relation_export, boundary_type: :project
        post ':id/export_relations' do
          check_rate_limit! :project_relations_export, scope: { user: current_user, project: user_project }

          response = ::BulkImports::ExportService
            .new(portable: user_project, user: current_user, batched: params[:batched])
            .execute

          if response.success?
            log_direct_transfer_audit_event(
              ::Import::BulkImports::Audit::Events::EXPORT_INITIATED,
              'Direct Transfer relations export initiated',
              current_user,
              user_project
            )

            accepted!
          else
            render_api_error!('Project relations export could not be started.', 500)
          end
        end

        desc 'Download a relations export for a project' do
          detail 'Downloads a project relations export file. By default, this endpoint is limited to 100 requests ' \
            'per minute for each user and project. ' \
            'The instance must meet the direct transfer prerequisites, including the `bulk_import_enabled` ' \
            'application setting. If the setting is disabled, a `404` is returned. This endpoint cannot be used ' \
            'with the file-based group import and export API.'
          success code: 200
          failure [
            { code: 400, message: 'Bad request' },
            { code: 401, message: 'Unauthorized' },
            { code: 403, message: 'Forbidden' },
            { code: 404, message: 'Not found' },
            { code: 429, message: 'Too many requests' },
            { code: 500, message: 'Internal Server Error' },
            { code: 503, message: 'Service unavailable' }
          ]
          tags ['project_import']
          produces %w[application/octet-stream application/gzip application/json]
        end
        params do
          requires :relation, type: String, project_portable: true, desc: 'Name of the project top-level relation to ' \
                                                                      'download or view.'
          optional :batched, type: Boolean, desc: 'If `true`, downloads the batch specified by `batch_number`. ' \
                                              'Set to `true` only for batched exports.'
          optional :batch_number, type: Integer, desc: 'Number of the export batch to download.'

          all_or_none_of :batched, :batch_number
        end
        route_setting :authorization, permissions: :download_project_relation_export, boundary_type: :project
        get ':id/export_relations/download' do
          check_rate_limit! :project_relations_export_download, scope: { user: current_user, project: user_project }

          export = user_project.bulk_import_exports.for_user_and_relation(current_user, params[:relation])
            .for_offline_export(nil).first

          break render_api_error!('Export not found', 404) unless export

          if params[:batched]
            batch = export.batches.find_by_batch_number(params[:batch_number])
            batch_file = batch&.upload&.export_file

            break render_api_error!('Export is not batched', 400) unless export.batched?
            break render_api_error!('Batch not found', 404) unless batch
            break render_api_error!('Batch file not found', 404) unless batch_file

            log_direct_transfer_audit_event(
              ::Import::BulkImports::Audit::Events::EXPORT_BATCH_DOWNLOADED,
              'Direct Transfer relation export batch downloaded',
              current_user,
              user_project
            )

            present_carrierwave_file!(batch_file)
          else
            file = export&.upload&.export_file

            break render_api_error!('Export is batched', 400) if export.batched?
            break render_api_error!('Export file not found', 404) unless file

            log_direct_transfer_audit_event(
              ::Import::BulkImports::Audit::Events::EXPORT_DOWNLOADED,
              'Direct Transfer relation export downloaded',
              current_user,
              user_project
            )

            present_carrierwave_file!(file)
          end
        end

        desc 'Retrieve the status of an relations export for a project' do
          detail 'Retrieves the status of a relations export for a project. The `status` is one of `-2` ' \
            '(pending), `0` (started), `1` (finished), or `-1` (failed). ' \
            'The instance must meet the direct transfer prerequisites, including the `bulk_import_enabled` ' \
            'application setting. If the setting is disabled, a `404` is returned. This endpoint cannot be used ' \
            'with the file-based group import and export API.'
          is_array true
          success code: 200, model: Entities::BulkImports::ExportStatus
          failure [
            { code: 401, message: 'Unauthorized' },
            { code: 403, message: 'Forbidden' },
            { code: 404, message: 'Not found' },
            { code: 503, message: 'Service unavailable' }
          ]
          tags ['project_import']
        end
        params do
          optional :relation, type: String, desc: 'Name of the project top-level relation to download or view.'
        end
        route_setting :authorization, permissions: :read_project_relation_export, boundary_type: :project
        get ':id/export_relations/status' do
          if params[:relation]
            export = user_project.bulk_import_exports.for_user_and_relation(current_user, params[:relation])
              .for_offline_export(nil).first

            break render_api_error!('Export not found', 404) unless export

            present export, with: Entities::BulkImports::ExportStatus
          else
            present user_project.bulk_import_exports.for_user(current_user).for_offline_export(nil),
              with: Entities::BulkImports::ExportStatus
          end
        end
      end
    end
  end
end
