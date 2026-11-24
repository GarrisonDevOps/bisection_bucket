# frozen_string_literal: true

module Ai
  module ActiveContext
    module References
      module Preprocessors
        module CodeRootNamespaceResolver
          extend ActiveSupport::Concern

          included do
            attr_writer :root_namespace_id
          end

          class_methods do
            def resolve_code_root_namespace(refs:, queue_name: nil)
              log_namespace_resolution(refs)

              with_batch_handling(
                refs,
                queue_name: queue_name,
                preprocessor: 'code_root_namespace_resolver') do
                root_namespace_ids_by_project_ids = Project.root_namespace_ids_by_project_ids(
                  refs.map(&:project_id).uniq
                )

                refs.each do |ref|
                  ref.root_namespace_id = root_namespace_ids_by_project_ids[ref.project_id]
                end

                log_namespace_resolution_success(refs)

                refs
              end
            end

            private

            def log_namespace_resolution(refs)
              ::ActiveContext::Logger.info(
                message: 'Resolving root_namespace_id for references',
                class_name: name,
                preprocessor: 'code_root_namespace_resolver',
                refs_count: refs.length
              )
            end

            def log_namespace_resolution_success(refs)
              root_namespace_ids = refs.filter_map(&:root_namespace_id)
              unique_root_namespace_ids = root_namespace_ids.uniq

              ::ActiveContext::Logger.info(
                message: 'Resolved root_namespace_id for references',
                class_name: name,
                preprocessor: 'code_root_namespace_resolver',
                refs_count: refs.length,
                refs_with_root_namespaces_count: root_namespace_ids.length,
                unique_root_namespace_ids: unique_root_namespace_ids
              )
            end
          end
        end
      end
    end
  end
end
