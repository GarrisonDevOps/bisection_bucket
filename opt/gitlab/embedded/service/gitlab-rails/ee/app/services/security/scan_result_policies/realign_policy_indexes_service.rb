# frozen_string_literal: true

module Security
  module ScanResultPolicies
    # Reads and approval rules keep a copy of the policy index, which goes stale when policies are
    # reordered. Unique indexes on reads and MR rules include it, so rows move through temporary
    # indexes first; the offset stays within smallint while policy indexes stay below 16768.
    class RealignPolicyIndexesService
      include ::Gitlab::ExclusiveLeaseHelpers

      TEMPORARY_INDEX_OFFSET = 16_000
      # Renewed before every UPDATE, so it only has to cover two statements of up to 15s each.
      LOCK_TTL = 1.minute
      LOCK_RETRIES = 20
      LOCK_SLEEP = 0.5
      MERGE_REQUEST_BATCH_SIZE = 20
      # Policies per configuration * rules per policy * actions per rule
      MAX_STALE_READS = Security::ScanResultPolicy::POLICIES_LIMIT * 5 * Security::ScanResultPolicy::APPROVERS_ACTIONS_LIMIT

      TooManyReadsError = Class.new(StandardError)

      def initialize(project:, policy_configuration:)
        @project = project
        @policy_configuration = policy_configuration
      end

      # Serialised per project: the fan-out runs one job per moved policy, and a job from an
      # older reorder must not overwrite indexes written by a newer one.
      #
      # Reads move last, so a realign that stops midway leaves them stale and the next one redoes it;
      # the MR sync also rewrites a rule's index from its project rule.
      def execute
        in_lock(lock_key, ttl: LOCK_TTL, retries: LOCK_RETRIES, sleep_sec: LOCK_SLEEP) do |_retried, lease|
          @lease = lease
          reads = stale_reads
          next if reads.empty?

          groups = reads.group_by(&:current_policy_index)
          # Project rules first: the MR sync locks the project rule before the MR rule.
          groups.each { |index, group| move_project_rules(group, index) }

          each_open_merge_request_batch { |merge_requests| realign_merge_request_rules(merge_requests, groups) }
          realign_reads(groups)
        end
      end

      private

      attr_reader :project, :policy_configuration, :lease

      def lock_key
        "security_policies:realign_policy_indexes:#{policy_configuration.id}:#{project.id}"
      end

      def update_rows(relation, updates)
        raise FailedToObtainLockError, 'Lost the realign lease' unless lease.renew

        relation.update_all(updates)
      end

      def stale_reads
        reads = project.scan_result_policy_reads.for_policy_configuration(policy_configuration)
          .with_stale_policy_index.limit(MAX_STALE_READS + 1).to_a
        raise TooManyReadsError, "More than #{MAX_STALE_READS} stale policy reads" if reads.size > MAX_STALE_READS

        reads
      end

      def each_open_merge_request_batch
        project.merge_requests.opened.each_batch(of: MERGE_REQUEST_BATCH_SIZE) { |batch| yield batch }
      end

      # approval_project_rules has no unique index on the policy index, so no temporary shift.
      # Bounded by the reads: a read has one project rule.
      def move_project_rules(reads, policy_index)
        update_rows(ApprovalProjectRule.for_scan_result_policy_read(reads), orchestration_policy_idx: policy_index)
      end

      # The unique index starts with merge_request_id, so batches cannot collide. Both statements use
      # the locked ids, so an MR merged or closed in between cannot keep the temporary index.
      def realign_merge_request_rules(merge_requests, groups)
        ApplicationRecord.transaction do
          rule_ids_by_read = ApprovalMergeRequestRule
            .for_merge_requests(merge_requests)
            .for_policy_configuration(policy_configuration.id)
            .for_scan_result_policy_read(groups.values.flatten)
            .lock_ids_by_scan_result_policy_read

          next if rule_ids_by_read.empty?

          shift_to_temporary_index(ApprovalMergeRequestRule, rule_ids_by_read.values.flatten)
          groups.each do |index, reads|
            rule_ids = rule_ids_by_read.values_at(*reads.map(&:id)).compact.flatten
            update_rows(ApprovalMergeRequestRule.id_in(rule_ids), orchestration_policy_idx: index)
          end
        end
      end

      # Reads of one policy share its index and differ by rule_idx, so they can move together without colliding.
      def realign_reads(groups)
        ids = groups.values.flatten.map(&:id)

        ApplicationRecord.transaction do
          # Held until the transaction commits
          Security::ScanResultPolicyRead.id_in(ids).locked_for_realign.to_a

          shift_to_temporary_index(Security::ScanResultPolicyRead, ids)
          groups.each do |index, reads|
            update_rows(Security::ScanResultPolicyRead.id_in(reads.map(&:id)), orchestration_policy_idx: index)
          end
        end
      end

      def shift_to_temporary_index(model, ids)
        shift = ['orchestration_policy_idx = orchestration_policy_idx - ?', TEMPORARY_INDEX_OFFSET]

        update_rows(model.id_in(ids), shift)
      end
    end
  end
end
