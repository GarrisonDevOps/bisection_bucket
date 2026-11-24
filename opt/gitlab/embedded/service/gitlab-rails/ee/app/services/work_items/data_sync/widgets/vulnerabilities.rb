# frozen_string_literal: true

module WorkItems
  module DataSync
    module Widgets
      class Vulnerabilities < Base
        include ::Gitlab::Utils::StrongMemoize

        def after_save_commit
          return unless params[:operation] == :move

          work_item.vulnerability_links.each_batch(**each_batch_params) do |vulnerability_links_batch|
            ::Vulnerabilities::IssueLink.insert_all(new_work_item_vulnerability_links(vulnerability_links_batch))
          end
        end

        def post_move_cleanup
          work_item.vulnerability_links.each_batch(**each_batch_params) do |vulnerability_links_batch|
            vulnerability_links_batch.delete_all
          end
        end

        private

        def new_work_item_vulnerability_links(vulnerability_links_batch)
          vulnerability_links_batch.map do |vulnerability_link|
            vulnerability_link.attributes.except("id").tap do |attrs|
              # project_id - is linked to the vulnerability and remains as such even upon work item move
              # https://gitlab.com/gitlab-org/gitlab/-/merge_requests/175025#note_2277006790
              attrs["issue_id"] = target_work_item.id
            end
          end
        end

        def each_batch_params
          { of: BATCH_SIZE, column: :vulnerability_id }
        end
        strong_memoize_attr :each_batch_params
      end
    end
  end
end
