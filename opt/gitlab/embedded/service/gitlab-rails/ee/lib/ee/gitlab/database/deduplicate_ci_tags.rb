# frozen_string_literal: true

module EE
  module Gitlab
    module Database
      module DeduplicateCiTags
        extend ::Gitlab::Utils::Override

        override :execute
        def execute
          if ::Gitlab::Saas.feature_available?(:deduplicate_ci_tags)
            logger.error "This rake task is not optimized for .com"
            return
          end

          super
        end

        private

        override :deduplicate_ci_taggings
        def deduplicate_ci_taggings(bad_tag_ids, tag_remap)
          super

          # rubocop:disable CodeReuse/ActiveRecord -- specific for this database task
          dast_profile_tag_ids = Dast::ProfileTag.where(tag_id: bad_tag_ids).distinct(:tag_id).pluck(:tag_id)
          count = dast_profile_tag_ids.count

          dast_profile_tag_ids.each do |bad_tag_id|
            new_tag_id = tag_remap.fetch(bad_tag_id)
            Dast::ProfileTag.where(tag_id: bad_tag_id).update_all(tag_id: new_tag_id) unless dry_run
          end
          # rubocop:enable CodeReuse/ActiveRecord

          logger.info("Updated tag_id on a batch of #{count} tags on #{Dast::ProfileTag.table_name}")
        end
      end
    end
  end
end
