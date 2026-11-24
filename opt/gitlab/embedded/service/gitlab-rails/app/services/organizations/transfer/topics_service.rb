# frozen_string_literal: true

module Organizations
  module Transfer
    class TopicsService
      include Gitlab::Utils::StrongMemoize

      BATCH_SIZE = 100

      def initialize(group:, old_organization:, new_organization:)
        @group = group
        @old_organization = old_organization
        @new_organization = new_organization
      end

      def execute
        avatar_transfer_pairs = []
        counter_deltas = Hash.new { |h, k| h[k] = { total: 0, non_private: 0 } }

        old_topics.each_batch(of: BATCH_SIZE) do |batch|
          new_topic_ids = copy_to_new_organization(batch)

          batch.each do |old_topic|
            new_topic_id = new_topic_ids.fetch(old_topic.name)
            next if new_topic_id == old_topic.id

            avatar_transfer_pairs << [old_topic.id, new_topic_id] if old_topic.avatar.present?
            repoint_and_accumulate_deltas(old_topic, new_topic_id, counter_deltas)
          end
        end

        flush_counter_deltas(counter_deltas)
        schedule_avatar_transfers(avatar_transfer_pairs) if avatar_transfer_pairs.any?
      end

      private

      attr_reader :group, :old_organization, :new_organization

      # rubocop:disable CodeReuse/ActiveRecord -- scoped queries for topic transfer
      def projects
        Project.in_namespace(group.self_and_descendant_ids(skope: Namespace))
      end
      strong_memoize_attr :projects

      def old_topics
        project_topics = Projects::ProjectTopic.joins(project: :namespace)
          .where("project_topics.topic_id = topics.id")
          .where("namespaces.traversal_ids @> '{?}'", group.id)

        Projects::Topic
          .where(organization_id: old_organization.id)
          .where_exists(project_topics)
      end

      # Skips model validations: old topics can fail current rules (for example, non-ASCII
      # names) but satisfy the table's constraints. Conflicting rows are skipped, so a same-name
      # topic is reused, and a slug owned by another target topic is retried without a slug.
      def copy_to_new_organization(old_topics)
        rows = old_topics.map do |old_topic|
          {
            organization_id: new_organization.id,
            name: old_topic.name,
            title: old_topic.title,
            description: old_topic.description,
            slug: old_topic.slug
          }
        end

        Projects::Topic.insert_all(rows, returning: false)
        new_topic_ids = new_topic_ids_by_name(rows)

        slug_conflicts = rows.reject { |row| new_topic_ids.key?(row[:name]) }
        return new_topic_ids if slug_conflicts.empty?

        Projects::Topic.insert_all(slug_conflicts.map { |row| row.merge(slug: nil) }, returning: false)
        new_topic_ids.merge(new_topic_ids_by_name(slug_conflicts))
      end

      # rubocop:disable Database/AvoidUsingPluckWithoutLimit -- bounded by BATCH_SIZE
      def new_topic_ids_by_name(rows)
        Projects::Topic
          .where(organization_id: new_organization.id, name: rows.pluck(:name))
          .pluck(:name, :id)
          .to_h
      end
      # rubocop:enable Database/AvoidUsingPluckWithoutLimit

      def repoint_and_accumulate_deltas(old_topic, new_topic_id, counter_deltas)
        scoped_project_topics = Projects::ProjectTopic
          .where(topic_id: old_topic.id, project_id: projects)

        already_assigned = Projects::ProjectTopic
          .from('project_topics AS pt_dup')
          .where(pt_dup: { topic_id: new_topic_id })
          .where('pt_dup.project_id = project_topics.project_id')

        non_private_count = non_private_project_count(old_topic)

        duplicates_deleted = scoped_project_topics.where_exists(already_assigned).delete_all
        moved_count = scoped_project_topics.update_all(topic_id: new_topic_id)

        total_removed = moved_count + duplicates_deleted
        counter_deltas[old_topic.id][:total] -= total_removed
        counter_deltas[old_topic.id][:non_private] -= non_private_count
        counter_deltas[new_topic_id][:total] += moved_count
        counter_deltas[new_topic_id][:non_private] += non_private_count
      end

      def non_private_project_count(topic)
        project_topics = Projects::ProjectTopic
            .where('project_topics.project_id = projects.id')
            .where(topic_id: topic.id)

        projects
          .where(visibility_level: [Gitlab::VisibilityLevel::INTERNAL, Gitlab::VisibilityLevel::PUBLIC])
          .where_exists(project_topics)
          .count
      end

      def flush_counter_deltas(counter_deltas)
        counter_deltas.each do |topic_id, deltas|
          next if deltas[:total] == 0 && deltas[:non_private] == 0

          Projects::Topic.where(id: topic_id).update_counters(
            total_projects_count: deltas[:total],
            non_private_projects_count: deltas[:non_private]
          )
        end
      end

      def schedule_avatar_transfers(pairs)
        # `group` is never saved by the transfer, so it cannot carry an after-commit
        # callback. The target topics are created in this transaction and the worker
        # returns early if it cannot see them yet.
        ActiveRecord.after_all_transactions_commit do
          pairs.each do |source_topic_id, target_topic_id|
            Organizations::TransferTopicAvatarWorker.perform_async(source_topic_id, target_topic_id)
          end
        end
      end
      # rubocop:enable CodeReuse/ActiveRecord
    end
  end
end
